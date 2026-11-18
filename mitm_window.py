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
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import netreg_mitm as mitm

IP = sys.argv[1] if len(sys.argv) > 1 else ""
MAC = sys.argv[2] if len(sys.argv) > 2 else ""
HOSTNAME = sys.argv[3] if len(sys.argv) > 3 else ""


class MitmUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Route traffic through this Mac — {IP or '(no target)'}")
        self.geometry("560x520")
        self.session = mitm.RouteSession()
        self.busy = False

        # --- authorization banner ----------------------------------------- #
        banner = tk.Label(
            self,
            text=("OWN-NETWORK / AUTHORIZED USE ONLY\n"
                  "This makes your Mac pretend to be the router so this device's "
                  "traffic flows through you. Only do this on a network you own "
                  "or are explicitly allowed to test."),
            bg="#7a1f1f", fg="white", justify="left", wraplength=520, padx=12, pady=10,
        )
        banner.pack(fill="x")

        info = ttk.LabelFrame(self, text="Target device")
        info.pack(fill="x", padx=12, pady=(12, 8))
        for label, val in (("IP", IP or "(unknown)"), ("MAC", MAC or "—"),
                           ("Hostname", HOSTNAME or "—")):
            row = ttk.Frame(info); row.pack(fill="x", padx=10, pady=2)
            ttk.Label(row, text=label + ":", width=10, anchor="w").pack(side="left")
            ttk.Label(row, text=val, anchor="w").pack(side="left")

        opts = ttk.Frame(self); opts.pack(fill="x", padx=12, pady=4)
        self.full_duplex = tk.BooleanVar(value=True)
        self.sniff = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Full duplex (also spoof the router)",
                        variable=self.full_duplex).pack(anchor="w")
        ttk.Checkbutton(opts, text="Capture a summary of the redirected traffic",
                        variable=self.sniff).pack(anchor="w")

        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self, variable=self.authorized, command=self._sync_buttons,
            text="I own this network or am explicitly authorized to test it.",
        ).pack(anchor="w", padx=14, pady=(8, 2))

        bar = ttk.Frame(self); bar.pack(fill="x", padx=12, pady=8)
        self.start_btn = ttk.Button(bar, text="Start routing", command=self.start, state="disabled")
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop & restore", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=10)

        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, wraplength=520,
                  justify="left", foreground="gray").pack(fill="x", padx=12, pady=(6, 10))

        ready, msg = mitm.preflight()
        self._ready = ready and bool(IP)
        if not IP:
            self.status_var.set("No target IP was passed — nothing to route.")
        elif not ready:
            self.status_var.set(msg)
        else:
            self.status_var.set("Tick the box above to enable Start.")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _sync_buttons(self):
        running = self.session.is_running()
        can_start = self._ready and self.authorized.get() and not running and not self.busy
        self.start_btn.config(state="normal" if can_start else "disabled")
        self.stop_btn.config(state="normal" if running and not self.busy else "disabled")

    def start(self):
        if not messagebox.askyesno(
            "Confirm",
            f"Route {IP}'s traffic through this Mac now?\n\n"
            "Only proceed on a network you own or are authorized to test.",
        ):
            return
        self.busy = True
        self._sync_buttons()
        self.status_var.set("Starting… you may be asked for your password.")

        def worker():
            ok, msg = self.session.start(IP, full_duplex=self.full_duplex.get(),
                                         sniff=self.sniff.get())
            def done():
                self.busy = False
                self.status_var.set(msg)
                self._sync_buttons()
            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def stop(self):
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
        try:
            if self.session.is_running():
                self.session.stop()  # always heal the network on close
        finally:
            self.destroy()


if __name__ == "__main__":
    MitmUI().mainloop()
