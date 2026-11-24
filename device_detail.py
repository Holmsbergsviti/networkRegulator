"""
device_detail.py -- detail window for one device on your network.

Can be opened two ways:

* In-process (fast path, no new program starts):
      import device_detail
      device_detail.open_detail(parent_window, ip, mac, hostname)
* Standalone, as its own process (kept for compatibility):
      python device_detail.py IP [MAC] [HOSTNAME]

Shows what we can learn about the device without touching it destructively:
its IP / MAC / hostname, whether it answers a ping, and which common TCP ports
are open (a plain connect-scan). Double-click an open port to open it with the
right app -- web ports in your browser, SSH/VNC/SMB/RDP in their handler.

Own-network use only -- this is for inspecting devices on a network you control.
"""
import re
import socket
import ssl
import subprocess
import sys
import threading
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox

import netreg_ui as ui
import netreg_probe as probe
import netreg_fingerprint as fingerprint
from netreg_backend import (scan_ports, service_name, ping_host,
                            resolve_hostname, vendor_for_mac)

try:
    import netreg_integrations as integrations
except Exception:
    integrations = None

# How to open a given port. Maps a TCP port to (url-scheme, friendly handler).
# The scheme is handed to the OS ("open" on macOS), which routes it to the
# browser, Finder, Screen Sharing, Microsoft Remote Desktop, a terminal, etc.
_DEFAULT_PORT = {"http": 80, "https": 443, "ftp": 21, "ssh": 22,
                 "telnet": 23, "vnc": 5900, "smb": 445, "afp": 548}
PORT_ACTIONS = {
    80:   ("http", "Open in browser"),
    81:   ("http", "Open in browser"),
    591:  ("http", "Open in browser"),
    631:  ("http", "Open printer page"),
    8000: ("http", "Open in browser"),
    8008: ("http", "Open in browser"),
    8080: ("http", "Open in browser"),
    8081: ("http", "Open in browser"),
    8888: ("http", "Open in browser"),
    443:  ("https", "Open in browser"),
    8443: ("https", "Open in browser"),
    21:   ("ftp", "Open in file browser"),
    22:   ("ssh", "Open in terminal (SSH)"),
    23:   ("telnet", "Open in terminal (Telnet)"),
    139:  ("smb", "Open in file browser"),
    445:  ("smb", "Open in file browser"),
    548:  ("afp", "Open in file browser"),
    5900: ("vnc", "Open screen sharing"),
    5901: ("vnc", "Open screen sharing"),
    3389: ("rdp", "Open Remote Desktop"),
}


def port_target(ip, port):
    """Return (url, human_action) for a port, or (None, None) if we don't have
    a built-in handler for it."""
    scheme_action = PORT_ACTIONS.get(port)
    if not scheme_action or not ip:
        return None, None
    scheme, action = scheme_action
    if scheme == "rdp":
        return f"rdp://full%20address=s:{ip}:{port}", action
    dp = _DEFAULT_PORT.get(scheme)
    hostport = ip if dp and port == dp else f"{ip}:{port}"
    return f"{scheme}://{hostport}", action


_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

# Ports we try when answering "would this show a page in a browser?" -- in the
# order we try them, most-likely first.
_WEB_CANDIDATES = (("http", 80), ("https", 443), ("http", 8080))


def probe_web(ip, timeout=1.2):
    """Does this device serve a web page? Try http/https on the usual ports and
    return info about the first one that answers, or None if none do.

    Returns {"url", "status", "server", "title"} on a hit. A 401/403 still
    counts as a hit -- the device HAS a web interface, it just wants a login.
    Self-signed certs (routers, cameras, printers) are accepted on purpose;
    this is an own-network inspection tool.
    """
    if not ip:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme, port in _WEB_CANDIDATES:
        url = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"
        req = urllib.request.Request(url, headers={"User-Agent": "LanLens"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return _web_result(url, resp.status, resp.headers.get("Server"),
                                   resp.read(8192))
        except urllib.error.HTTPError as e:
            # Got an HTTP response (e.g. 401 Unauthorized) -> there IS a web UI.
            body = b""
            try:
                body = e.read(8192)
            except Exception:
                pass
            return _web_result(url, e.code, e.headers.get("Server") if e.headers else None, body)
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError):
            continue
        except Exception:
            continue
    return None


def _web_result(url, status, server, body):
    title = ""
    if body:
        m = _TITLE_RE.search(body)
        if m:
            try:
                title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:60]
            except Exception:
                title = ""
    return {"url": url, "status": status, "server": (server or "").strip(), "title": title}


def web_label(info):
    """A short human description of a probe_web() result."""
    if not info:
        return "No web page", "idle"
    bits = [info["url"]]
    detail = info["title"] or info["server"]
    if detail:
        bits.append(detail)
    note = "  (needs login)" if info["status"] in (401, 403) else ""
    return "✓ Yes — " + " · ".join(bits) + note, "ok"


def open_url(url):
    """Hand a url/scheme to the OS to open with whatever app is registered."""
    if sys.platform == "darwin":
        subprocess.Popen(["open", url])
    elif sys.platform.startswith("win"):
        import os
        os.startfile(url)  # noqa: S606 -- user-initiated, own-network tool
    else:
        subprocess.Popen(["xdg-open", url])


def open_detail(master, ip="", mac="", hostname=""):
    """Open the detail view in the current process as a child window. Returns
    the window. This is the fast path -- no new interpreter/Tk start-up, so the
    window appears immediately."""
    win = DeviceDetailUI(master, ip, mac, hostname)
    ui.raise_window(win, master)
    return win


class DeviceDetailUI(tk.Toplevel):
    def __init__(self, master, ip="", mac="", hostname=""):
        super().__init__(master)
        self.ip = ip or ""
        self.mac = mac or ""
        self.hostname = hostname or ""
        self.scanning = False
        self._web_info = None

        self.title(f"Device {self.ip or '(unknown)'}")
        self.geometry("580x600")
        self.minsize(480, 460)

        ui.apply_theme(self)
        ui.header(self, self.ip or "Device",
                  self.hostname or "Inspect this device on your network")

        # --- info card -----------------------------------------------------
        info = ttk.LabelFrame(self, text="Device", padding=(4, 6))
        info.pack(fill="x", padx=16, pady=(14, 10))
        self.vars = {}
        for label in ("IP", "MAC", "Vendor", "Type", "Hostname", "Reachable", "Web interface"):
            row = ttk.Frame(info, style="Card.TFrame")
            row.pack(fill="x", padx=10, pady=3)
            ttk.Label(row, text=label, width=13, anchor="w", style="Field.TLabel").pack(side="left")
            var = tk.StringVar(value="…")
            self.vars[label] = var
            ttk.Label(row, textvariable=var, anchor="w", style="Value.TLabel").pack(
                side="left", fill="x", expand=True)

        self.vars["IP"].set(self.ip or "(unknown)")
        self.vars["MAC"].set(self.mac or "—")
        self.vars["Vendor"].set((vendor_for_mac(self.mac) or "unknown") if self.mac else "—")
        self._open_ports = []        # filled as the scan finds open ports
        self.vars["Type"].set("…")
        self.vars["Hostname"].set(self.hostname or "…")
        self.vars["Reachable"].set("checking…")
        self.vars["Web interface"].set("checking…" if self.ip else "—")
        self._refresh_type()  # first guess from vendor/hostname; refined by the scan

        # --- action bar ----------------------------------------------------
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=16, pady=(0, 8))
        self.scan_btn = ttk.Button(bar, text="Scan Ports", style="Accent.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side="right")
        self.status = ui.StatusBar(bar)
        self.status.pack(side="left")
        self.status.set("Ready.", "idle")

        # Inspect print traffic: check whether jobs sent to this printer from
        # this Mac are encrypted. Enabled once we have an IP; it highlights
        # itself when a print port (9100/631/515) turns up in the scan.
        self.print_btn = ttk.Button(bar, text="Inspect print traffic",
                                    command=self.inspect_print, state="disabled")
        self.print_btn.pack(side="right", padx=8)
        self._print_ports_found = False

        # --- risk summary (hidden until something is flagged) --------------
        self.risk_lbl = tk.Label(
            self, text="", bg=ui.DANGER, fg="white", justify="left",
            anchor="w", wraplength=540, padx=12, pady=8)
        # packed/unpacked by _refresh_risk_banner so it takes no space when empty

        # --- open-ports table ----------------------------------------------
        body = ttk.Frame(self)
        self._ports_body = body
        body.pack(fill="both", expand=True, padx=16, pady=(0, 6))
        cols = ("Port", "Service", "Version", "Open with")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", height=12)
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        for c, w, anchor in (("Port", 64, "center"), ("Service", 130, "w"),
                             ("Version", 200, "w"), ("Open with", 150, "w")):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor=anchor)
        ui.style_tree(self.tree)
        ui.enable_copy(self.tree)
        self.tree.tag_configure("openable", foreground=ui.ACCENT)
        # A risky service (Telnet, plain FTP, exposed SMB, …) is flagged in red;
        # configured last so its colour wins over the "openable" accent.
        self.tree.tag_configure("risk", foreground="#ffffff", background=ui.DANGER)
        self.tree.bind("<Double-1>", self.on_port_double_click)
        self._empty_iid = None
        self._risks = {}        # port -> reason, filled as the scan progresses
        self._web_risk = ""     # set by the web probe if the page needs no login

        ttk.Label(
            self,
            text=("Open TCP ports from a plain connect-scan of common ports, with "
                  "the service version where it announces one. Risky services "
                  "(Telnet, plain FTP, exposed SMB, a no-login web page) are "
                  "flagged in red and summarised above. Double-click a port to "
                  "open it — web ports launch your browser, SSH / VNC / "
                  "file-sharing open their app. For devices on a network you control."),
            style="Muted.TLabel", wraplength=540, justify="left",
        ).pack(fill="x", padx=16, pady=(0, 12))

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if not self.ip:
            self.status.set("No IP for this device — nothing to scan.", "warn")
            self.scan_btn.config(state="disabled")
            self.vars["Reachable"].set("—")
        else:
            self.print_btn.config(state="normal")
            # Each slow lookup gets its OWN thread so none blocks the others.
            # (Reverse-DNS and an ignored ping used to delay the web check,
            # leaving "Web interface: checking…" stuck for seconds.)
            threading.Thread(target=self._prime, daemon=True).start()
            threading.Thread(target=self._probe_web, daemon=True).start()
            self.after(300, self.start_scan)

    def _prime(self):
        if not self.hostname:
            name = resolve_hostname(self.ip)
            self.after(0, self.vars["Hostname"].set, name or "(no reverse DNS)")
            self.after(0, self._refresh_type)  # hostname can sharpen the guess
        ok, latency = ping_host(self.ip)
        self.after(0, self.vars["Reachable"].set,
                   (f"yes ({latency})" if ok else "no reply to ping"))

    def _refresh_type(self):
        """Guess what KIND of device this is from the cheap signals we already
        have (vendor, open ports, hostname) and show it. Re-run as those signals
        arrive; it's pure and never touches the network."""
        vendor = (vendor_for_mac(self.mac) or "") if self.mac else ""
        host = self.hostname or ""
        shown = self.vars["Hostname"].get()
        if shown and not shown.startswith(("…", "(")):
            host = shown
        try:
            r = fingerprint.classify(vendor=vendor, ports=self._open_ports,
                                     hostname=host)
        except Exception:
            return
        if r.kind and r.kind != "Unknown":
            self.vars["Type"].set(f"{r.kind}  ({r.confidence} confidence)")
        else:
            self.vars["Type"].set("Unknown")

    def _probe_web(self):
        info = probe_web(self.ip)
        text, _state = web_label(info)
        self._web_info = info
        risk = probe.web_risk(info)
        if risk:
            text += "  ⚠ no login"
        self.after(0, self._apply_web_result, text, risk)

    def _apply_web_result(self, text, risk):
        self.vars["Web interface"].set(text)
        if risk:
            self._web_risk = risk
            self._refresh_risk_banner()

    def start_scan(self):
        if self.scanning or not self.ip:
            return
        self.scanning = True
        self.scan_btn.config(state="disabled")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._empty_iid = None
        self.status.set("Scanning common ports…", "work")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        found = {"n": 0}

        def on_open(port):
            found["n"] += 1
            self.after(0, self._add_port, port)

        try:
            fast = None
            if integrations is not None:
                try:
                    fast = integrations.fast_port_scan(self.ip)
                except Exception:
                    fast = None
            if fast is not None:
                for port in fast:
                    on_open(port)
                scanner = "fast scanner"
            else:
                scan_ports(self.ip, on_open=on_open)
                scanner = "common ports"
            if found["n"]:
                msg, state = (f"Scan complete ({scanner}) — {found['n']} open port(s). "
                              "Double-click a port to open it.", "ok")
            else:
                msg, state = ("Scan complete — no common ports open. That's normal for "
                              "phones, laptops and most IoT devices, which don't run "
                              "services you can connect to.", "idle")
        except Exception as e:
            msg, state = f"Scan error: {e}", "error"
        self.after(0, self._scan_done, msg, state)

    def _add_port(self, port):
        try:
            p = int(port)
        except (ValueError, TypeError):
            p = None
        url, action = port_target(self.ip, p)
        if p is not None and p not in self._open_ports:
            self._open_ports.append(p)
            self._refresh_type()  # open ports sharpen the device-type guess
        iid = f"port:{port}"
        if not self.tree.exists(iid):
            self.tree.insert("", "end", iid=iid,
                             values=(port, service_name(port) or "unknown",
                                     "…", action or "—"))
        self._restripe()
        # Risk flag (instant + pure): red-tag the row and add it to the summary.
        reason = probe.risk_for_port(p) if p is not None else ""
        if reason:
            self._risks[p] = reason
            self._refresh_risk_banner()
            self._restripe()
        # Version / banner: grab in the background so the UI never blocks.
        if p is not None:
            threading.Thread(target=self._fill_version, args=(p, iid),
                             daemon=True).start()
        # A print port on this device? Nudge the user toward the capture tool.
        if p in (9100, 631, 515) and not self._print_ports_found:
            self._print_ports_found = True
            self.print_btn.config(text="Inspect print traffic ✱")
            self.status.set(
                "Looks like a printer — use \"Inspect print traffic\" to check "
                "whether your print jobs are encrypted.", "idle")

    def inspect_print(self):
        if not self.ip:
            return
        name = self.hostname or self.vars["Hostname"].get() or ""
        self.status.set("Opening print-traffic capture…", "work")
        # Open in-process so it appears instantly, and show the real error at
        # once if it fails instead of launching a slow separate program that
        # would fail the same way from a cloud-synced folder.
        def _open():
            import print_capture_window
            return print_capture_window.open_capture(self, self.ip, name)

        if ui.open_child_window(_open, "the print-traffic capture", parent=self) is None:
            self.status.set("Couldn't open print capture — see the error.", "error")

    def _restripe(self):
        """Zebra-stripe the rows, colour openable rows in the accent, and flag
        risky services in red. 'risk' is appended last so its red wins over the
        'openable' accent when a row is both."""
        for i, iid in enumerate(self.tree.get_children()):
            vals = self.tree.item(iid, "values")
            tags = ["even" if i % 2 else "odd"]
            try:
                p = int(vals[0])
            except (ValueError, TypeError, IndexError):
                p = None
            if p is not None and port_target(self.ip, p)[0]:
                tags.append("openable")
            if p is not None and p in self._risks:
                tags.append("risk")
            self.tree.item(iid, tags=tuple(tags))

    def _fill_version(self, port, iid):
        """Background: fetch a banner/version string for one port and show it."""
        text = ""
        if port in probe.HTTPS_PORTS and self._web_info:
            text = self._web_info.get("server") or self._web_info.get("title") or ""
        if not text:
            text = probe.grab_banner(self.ip, port)
        if not text and port in probe.HTTPS_PORTS:
            text = "TLS (encrypted)"
        if text:
            self.after(0, self._set_version, iid, text)

    def _set_version(self, iid, text):
        if self.tree.exists(iid):
            vals = list(self.tree.item(iid, "values"))
            if len(vals) >= 3:
                vals[2] = text
                self.tree.item(iid, values=vals)

    def _refresh_risk_banner(self):
        """Show/update the red risk summary above the table, or hide it when
        there's nothing flagged."""
        lines = [f"Port {p}: {self._risks[p]}" for p in sorted(self._risks)]
        if self._web_risk:
            lines.append(self._web_risk)
        if not lines:
            self.risk_lbl.pack_forget()
            return
        header = "⚠  Security risk" if len(lines) == 1 else f"⚠  {len(lines)} security risks"
        self.risk_lbl.config(text=header + "\n" + "\n".join("• " + l for l in lines))
        if not self.risk_lbl.winfo_ismapped():
            self.risk_lbl.pack(fill="x", padx=16, pady=(0, 8), before=self._ports_body)

    def on_port_double_click(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        try:
            port = int(vals[0])
        except (ValueError, TypeError, IndexError):
            return
        url, action = port_target(self.ip, port)
        service = vals[1] if len(vals) > 1 else ""
        if url:
            self.status.set(f"Opening port {port} ({service})…", "work")
            try:
                open_url(url)
            except Exception as e:
                self.status.set(f"Couldn't open port {port}: {e}", "error")
            return
        # No built-in handler: offer the browser as a best-effort guess.
        if messagebox.askyesno(
                f"Port {port}",
                f"Port {port} ({service or 'unknown'}) has no built-in handler.\n\n"
                "Try opening it in your browser?"):
            try:
                open_url(f"http://{self.ip}:{port}")
                self.status.set(f"Opening http://{self.ip}:{port} …", "work")
            except Exception as e:
                self.status.set(f"Couldn't open port {port}: {e}", "error")

    def _scan_done(self, msg, state="idle"):
        self.scanning = False
        self.status.set(msg, state)
        self.scan_btn.config(state="normal")
        if not self.tree.get_children():
            self._empty_iid = self.tree.insert(
                "", "end", values=("—", "No open ports found", "", ""))

    def _on_close(self):
        self.destroy()


if __name__ == "__main__":
    IP = sys.argv[1] if len(sys.argv) > 1 else ""
    MAC = sys.argv[2] if len(sys.argv) > 2 else ""
    HOSTNAME = sys.argv[3] if len(sys.argv) > 3 else ""
    root = tk.Tk()
    root.withdraw()  # the Toplevel below is the visible window
    win = DeviceDetailUI(root, IP, MAC, HOSTNAME)
    win.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
