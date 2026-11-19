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
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkRegulator"})
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
        for label in ("IP", "MAC", "Vendor", "Hostname", "Reachable", "Web interface"):
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
        self.vars["Hostname"].set(self.hostname or "…")
        self.vars["Reachable"].set("checking…")
        self.vars["Web interface"].set("checking…" if self.ip else "—")

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

        # --- open-ports table ----------------------------------------------
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 6))
        cols = ("Port", "Proto", "Service", "Open with")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", height=12)
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        for c, w, anchor in (("Port", 70, "center"), ("Proto", 70, "center"),
                             ("Service", 190, "w"), ("Open with", 180, "w")):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor=anchor)
        ui.style_tree(self.tree)
        self.tree.tag_configure("openable", foreground=ui.ACCENT)
        self.tree.bind("<Double-1>", self.on_port_double_click)
        self._empty_iid = None

        ttk.Label(
            self,
            text=("Open TCP ports from a plain connect-scan of common ports. "
                  "Double-click a port to open it — web ports launch your browser, "
                  "SSH / VNC / file-sharing open their app. For devices on a network you control."),
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
        ok, latency = ping_host(self.ip)
        self.after(0, self.vars["Reachable"].set,
                   (f"yes ({latency})" if ok else "no reply to ping"))

    def _probe_web(self):
        info = probe_web(self.ip)
        text, _state = web_label(info)
        self._web_info = info
        self.after(0, self.vars["Web interface"].set, text)

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
        self.tree.insert("", "end", values=(port, "tcp", service_name(port) or "unknown",
                                            action or "—"))
        self._restripe()
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
        # Open in-process so it appears instantly; fall back to a subprocess,
        # then a visible error, rather than silently doing nothing.
        try:
            import print_capture_window
            print_capture_window.open_capture(self, self.ip, name)
        except Exception as e:
            try:
                subprocess.Popen([sys.executable, "print_capture_window.py",
                                 self.ip, name])
            except Exception:
                messagebox.showerror(
                    "Couldn't open print capture",
                    f"Opening the print-traffic capture failed:\n\n{e}")

    def _restripe(self):
        """Zebra-stripe the rows and keep openable rows coloured in the accent.
        A row carries both a stripe tag (background) and, if it has a handler,
        the 'openable' tag (foreground) -- the two options don't conflict."""
        for i, iid in enumerate(self.tree.get_children()):
            vals = self.tree.item(iid, "values")
            tags = ["even" if i % 2 else "odd"]
            try:
                if port_target(self.ip, int(vals[0]))[0]:
                    tags.append("openable")
            except (ValueError, TypeError, IndexError):
                pass
            self.tree.item(iid, tags=tuple(tags))

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
        service = vals[2] if len(vals) > 2 else ""
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
                "", "end", values=("—", "", "No open ports found", ""))

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
