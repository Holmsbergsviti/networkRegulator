"""
mitm_window.py -- route one device's traffic through this machine (bettercap).

Launched by the devices window when you choose "Route via this Mac":
    python mitm_window.py IP [MAC] [HOSTNAME]

====================  OWN-NETWORK / AUTHORIZED USE ONLY  ====================
This impersonates the router so the selected device's traffic flows through
your computer. Use it ONLY on a network you own or are explicitly authorized to
test. The Start button stays disabled until you confirm that below.
============================================================================
"""
import os
import re
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import socket

import netreg_ui as ui
import netreg_mitm as mitm
import netreg_traffic as nt
import netreg_bandwidth as bw

# Strip terminal colour / control sequences bettercap writes, so the pane shows
# clean text.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

def open_route(master, ip="", mac="", hostname="", cut=False):
    """Open the route/MITM window in the current process as a child window, so
    it appears immediately instead of starting a separate program.

    `cut=True` opens it in "cut off" mode: intercept the device's traffic but
    do NOT forward it to the router, so the device loses its connection."""
    win = MitmUI(master, ip, mac, hostname, cut)
    ui.raise_window(win, master)
    return win


class MitmUI(tk.Toplevel):
    def __init__(self, master, ip="", mac="", hostname="", cut=False):
        super().__init__(master)
        self.ip = ip or ""
        self.mac = mac or ""
        self.hostname = hostname or ""
        self.cut = bool(cut)
        if self.cut:
            self.title(f"Cut off device — {self.ip or '(no target)'}")
        else:
            self.title(f"Route traffic through this Mac — {self.ip or '(no target)'}")
        self.geometry("640x700")
        self.minsize(560, 560)
        ui.apply_theme(self)
        self.session = mitm.RouteSession()
        self.busy = False
        self._tailing = False
        self._tail_pos = 0
        self.summary = nt.TrafficSummary(self.ip or None)
        self.meter = bw.BandwidthMeter(self.ip or None)  # live throughput tally
        self._resolving = set()  # remote IPs a lookup thread is already working

        # --- authorization banner ----------------------------------------- #
        base, bold, title, small, mono = ui.fonts()
        if self.cut:
            banner_text = ("⚠  OWN-NETWORK / AUTHORIZED USE ONLY\n"
                           "This makes your Mac pretend to be the router and then "
                           "DROPS this device's traffic instead of passing it on, "
                           "so the device loses its internet while staying on the "
                           "Wi-Fi. Only do this on a network you own or are "
                           "explicitly allowed to test.")
        else:
            banner_text = ("⚠  OWN-NETWORK / AUTHORIZED USE ONLY\n"
                           "This makes your Mac pretend to be the router so this "
                           "device's traffic flows through you. Only do this on a "
                           "network you own or are explicitly allowed to test.")
        banner = tk.Label(
            self, text=banner_text,
            bg=ui.DANGER, fg="white", justify="left", wraplength=560,
            padx=16, pady=12, font=base, anchor="w",
        )
        banner.pack(fill="x")

        info = ttk.LabelFrame(self, text="Target device")
        info.pack(fill="x", padx=12, pady=(12, 8))
        for label, val in (("IP", self.ip or "(unknown)"), ("MAC", self.mac or "—"),
                           ("Hostname", self.hostname or "—")):
            row = ttk.Frame(info); row.pack(fill="x", padx=10, pady=2)
            ttk.Label(row, text=label + ":", width=10, anchor="w").pack(side="left")
            ttk.Label(row, text=val, anchor="w").pack(side="left")

        opts = ttk.Frame(self); opts.pack(fill="x", padx=12, pady=4)
        self.full_duplex = tk.BooleanVar(value=True)
        self.sniff = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Full duplex (also spoof the router)",
                        variable=self.full_duplex).pack(anchor="w")
        sniff_text = ("Show a live summary of what the device tries to reach"
                      if self.cut else
                      "Show a live summary of the redirected traffic")
        ttk.Checkbutton(opts, text=sniff_text,
                        variable=self.sniff).pack(anchor="w")

        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self, variable=self.authorized, command=self._sync_buttons,
            text="I own this network or am explicitly authorized to test it.",
        ).pack(anchor="w", padx=14, pady=(8, 2))

        bar = ttk.Frame(self); bar.pack(fill="x", padx=12, pady=8)
        start_text = "Start cutting off" if self.cut else "Start routing"
        self.start_btn = ttk.Button(bar, text=start_text, style="Accent.TButton",
                                    command=self.start, state="disabled")
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop & restore", style="Danger.TButton",
                                   command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=10)

        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, wraplength=560,
                  justify="left", foreground="gray").pack(fill="x", padx=12, pady=(6, 6))

        # --- live traffic pane: grouped summary + raw toggle --------------- #
        traffic = ttk.LabelFrame(self, text="Redirected traffic")
        traffic.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        # grouped summary table (default view)
        cols = ("server", "packets", "data", "proto", "ports")
        self.tree = ttk.Treeview(traffic, columns=cols, show="headings", height=11)
        for c, text, w, anchor in (
            ("server", "Server (the device talked to)", 300, "w"),
            ("packets", "Packets", 70, "e"),
            ("data", "Data", 80, "e"),
            ("proto", "Proto", 70, "center"),
            ("ports", "Ports", 90, "w"),
        ):
            self.tree.heading(c, text=text)
            self.tree.column(c, width=w, anchor=anchor)
        self.tree_vsb = ttk.Scrollbar(traffic, orient="vertical",
                                      command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.tree_vsb.set)
        ui.style_tree(self.tree)

        # raw per-packet log (hidden until toggled)
        self.traffic_text = tk.Text(traffic, height=11, wrap="none",
                                    state="disabled", font=("Menlo", 11),
                                    background="#111317", foreground="#d6dde6")
        self.text_vsb = ttk.Scrollbar(traffic, orient="vertical",
                                      command=self.traffic_text.yview)
        self.traffic_text.configure(yscrollcommand=self.text_vsb.set)

        self._show_summary()  # pack the table

        # live per-device throughput (updates as traffic flows through)
        self.bw_var = tk.StringVar(value="Throughput: —")
        ttk.Label(self, textvariable=self.bw_var, anchor="w",
                  style="Field.TLabel").pack(fill="x", padx=14, pady=(2, 0))

        bottom = ttk.Frame(self); bottom.pack(fill="x", padx=12, pady=(0, 8))
        self.show_raw = tk.BooleanVar(value=False)
        ttk.Checkbutton(bottom, text="Show raw packets instead of the grouped summary",
                        variable=self.show_raw, command=self._toggle_view).pack(anchor="w")
        if self.cut:
            hint_default = ("Start cutting off to drop this device's connection. "
                            "Its traffic reaches this Mac but is not passed on to "
                            "the router, so it can't reach the internet or the LAN "
                            "until you press Stop.")
        else:
            hint_default = ("Start routing to see which servers this device talks "
                            "to. HTTPS stays encrypted, so you'll see the servers "
                            "and how much data — not page contents.")
        self.hint_var = tk.StringVar(value=hint_default)
        ttk.Label(self, textvariable=self.hint_var, wraplength=580,
                  justify="left", foreground="gray").pack(fill="x", padx=12, pady=(0, 8))

        ready, msg = mitm.preflight()
        self._ready = ready and bool(self.ip)
        if not self.ip:
            self.status_var.set("No target IP was passed — nothing to route.")
        elif not ready:
            self.status_var.set(msg)
        else:
            self.status_var.set("Tick the box above to enable Start.")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _show_summary(self):
        self.traffic_text.pack_forget()
        self.text_vsb.pack_forget()
        self.tree_vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

    def _show_raw(self):
        self.tree.pack_forget()
        self.tree_vsb.pack_forget()
        self.text_vsb.pack(side="right", fill="y")
        self.traffic_text.pack(side="left", fill="both", expand=True)

    def _toggle_view(self):
        if self.show_raw.get():
            self._show_raw()
        else:
            self._show_summary()

    def _append_raw(self, text):
        at_end = self.traffic_text.yview()[1] >= 0.999
        self.traffic_text.config(state="normal")
        self.traffic_text.insert("end", text)
        # keep the raw buffer from growing without bound
        if int(self.traffic_text.index("end-1c").split(".")[0]) > 4000:
            self.traffic_text.delete("1.0", "2000.0")
        self.traffic_text.config(state="disabled")
        if at_end:
            self.traffic_text.see("end")

    def _render_summary(self):
        rows = self.summary.rows()
        self.tree.delete(*self.tree.get_children())
        total = 0
        for r in rows:
            total += r["packets"]
            server = r["name"] or r["host"]
            if r["name"]:
                server = f"{r['name']}  ({r['host']})"
            self.tree.insert("", "end", values=(
                server, r["packets"], nt.human_bytes(r["bytes"]),
                r["protos"], r["ports"]))
        ui.restripe(self.tree)
        if rows:
            self.hint_var.set(
                f"{len(rows)} server(s), {total} packets so far. HTTPS stays "
                f"encrypted — you see who the device talks to and how much, "
                f"not page contents.")

    def _render_bandwidth(self):
        """Show the device's current throughput (and totals) from the meter."""
        r = self.meter.rate()
        t = self.meter.totals()
        self.bw_var.set(
            f"Throughput:  ↓ {bw.human_rate(r['down'])}   ↑ {bw.human_rate(r['up'])}"
            f"      total {nt.human_bytes(t['total'])} in {t['packets']} packets")

    def _resolve_names(self):
        """Kick off reverse-DNS for any remote IP we haven't named yet, on a
        background thread so the UI never blocks."""
        for host in self.summary.hosts_without_names():
            if host in self._resolving:
                continue
            self._resolving.add(host)

            def lookup(h=host):
                name = ""
                try:
                    old = socket.getdefaulttimeout()
                    socket.setdefaulttimeout(1.5)
                    try:
                        name = socket.gethostbyaddr(h)[0]
                    finally:
                        socket.setdefaulttimeout(old)
                except Exception:
                    name = ""
                # record even an empty result so we don't retry forever
                self.after(0, lambda: self.summary.set_name(h, name or h))
            threading.Thread(target=lookup, daemon=True).start()

    def _start_tailing(self):
        """Begin following the session's traffic log into the pane."""
        if not getattr(self.session, "log_path", None):
            return
        self._tailing = True
        self._tail_pos = 0
        self.summary = nt.TrafficSummary(self.ip or None)
        self.meter = bw.BandwidthMeter(self.ip or None)
        self.bw_var.set("Throughput: —")
        self.tree.delete(*self.tree.get_children())
        self.after(500, self._poll_log)

    def _stop_tailing(self):
        self._tailing = False

    def _poll_log(self):
        if not self._tailing:
            return
        path = getattr(self.session, "log_path", None)
        if path and os.path.exists(path):
            try:
                with open(path, "r", errors="replace") as f:
                    f.seek(self._tail_pos)
                    chunk = f.read()
                    self._tail_pos = f.tell()
                if chunk:
                    clean = _ANSI.sub("", chunk)
                    self.summary.add_text(clean)
                    self.meter.add_text(clean)
                    self._append_raw(clean)
                    self._resolve_names()
                    self._render_summary()
                    self._render_bandwidth()
            except Exception:
                pass
        self.after(700, self._poll_log)

    def _sync_buttons(self):
        running = self.session.is_running()
        can_start = self._ready and self.authorized.get() and not running and not self.busy
        self.start_btn.config(state="normal" if can_start else "disabled")
        self.stop_btn.config(state="normal" if running and not self.busy else "disabled")

    def start(self):
        if self.cut:
            prompt = (f"Cut {self.ip} off the network now?\n\n"
                      "Its traffic will reach this Mac but won't be forwarded to "
                      "the router, so the device loses its connection until you "
                      "press Stop. Only proceed on a network you own or are "
                      "authorized to test.")
        else:
            prompt = (f"Route {self.ip}'s traffic through this Mac now?\n\n"
                      "Only proceed on a network you own or are authorized to test.")
        if not messagebox.askyesno("Confirm", prompt):
            return
        self.busy = True
        self._sync_buttons()
        self.status_var.set("Starting… you may be asked for your password.")

        def worker():
            ok, msg = self.session.start(self.ip, full_duplex=self.full_duplex.get(),
                                         sniff=self.sniff.get(), ban=self.cut)
            def done():
                self.busy = False
                self.status_var.set(msg)
                if ok and getattr(self.session, "log_path", None):
                    self._start_tailing()
                self._sync_buttons()
            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def stop(self):
        self._stop_tailing()
        self.busy = True
        self._sync_buttons()
        self.status_var.set("Stopping and restoring the network…")

        def worker():
            ok, msg = self.session.stop()
            def done():
                self.busy = False
                self.status_var.set(msg)
                self._sync_buttons()
            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self):
        self._stop_tailing()
        try:
            if self.session.is_running():
                self.session.stop()  # always heal the network on close
        finally:
            self.destroy()


if __name__ == "__main__":
    CUT = "--cut" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--cut"]
    IP = args[0] if len(args) > 0 else ""
    MAC = args[1] if len(args) > 1 else ""
    HOSTNAME = args[2] if len(args) > 2 else ""
    root = tk.Tk()
    root.withdraw()  # the Toplevel below is the visible window
    win = MitmUI(root, IP, MAC, HOSTNAME, CUT)
    win.protocol("WM_DELETE_WINDOW", lambda: (win._on_close(), root.destroy()))
    root.mainloop()
