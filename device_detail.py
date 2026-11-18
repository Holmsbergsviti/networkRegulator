"""
device_detail.py -- detail window for one device on your network.

Launched by the devices window when you double-click a device:
    python device_detail.py IP [MAC] [HOSTNAME]

Shows what we can learn about the device without touching it destructively:
its IP / MAC / hostname, whether it answers a ping, and which common TCP ports
are open (a plain connect-scan). Own-network use only -- this is for inspecting
devices on a network you control.
"""
import sys
import threading
import tkinter as tk
from tkinter import ttk

from netreg_backend import scan_ports, service_name, ping_host, resolve_hostname

IP = sys.argv[1] if len(sys.argv) > 1 else ""
MAC = sys.argv[2] if len(sys.argv) > 2 else ""
HOSTNAME = sys.argv[3] if len(sys.argv) > 3 else ""


class DeviceDetailUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Device {IP or '(unknown)'}")
        self.geometry("560x560")
        self.scanning = False

        info = ttk.LabelFrame(self, text="Device")
        info.pack(fill="x", padx=12, pady=(12, 8))
        self.vars = {}
        for label in ("IP", "MAC", "Hostname", "Reachable"):
            row = ttk.Frame(info)
            row.pack(fill="x", padx=10, pady=3)
            ttk.Label(row, text=label + ":", width=11, anchor="w").pack(side="left")
            var = tk.StringVar(value="…")
            self.vars[label] = var
            ttk.Label(row, textvariable=var, anchor="w").pack(side="left", fill="x", expand=True)

        self.vars["IP"].set(IP or "(unknown)")
        self.vars["MAC"].set(MAC or "—")
        self.vars["Hostname"].set(HOSTNAME or "…")
        self.vars["Reachable"].set("checking…")

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=12, pady=(0, 6))
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(bar, textvariable=self.status_var).pack(side="left")
        self.scan_btn = ttk.Button(bar, text="Scan Ports", command=self.start_scan)
        self.scan_btn.pack(side="right")

        cols = ("Port", "Proto", "Service")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=14)
        for c, w in (("Port", 90), ("Proto", 90), ("Service", 320)):
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        ttk.Label(
            self,
            text=("Open TCP ports found by a plain connect-scan of common ports. "
                  "For devices on a network you control."),
            foreground="gray", wraplength=520, justify="left",
        ).pack(fill="x", padx=12, pady=(0, 10))

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        if not IP:
            self.status_var.set("No IP for this device — nothing to scan.")
            self.scan_btn.config(state="disabled")
            self.vars["Reachable"].set("—")
        else:
            # fill in hostname + reachability in the background, then auto-scan
            threading.Thread(target=self._prime, daemon=True).start()
            self.after(300, self.start_scan)

    def _prime(self):
        if not HOSTNAME:
            name = resolve_hostname(IP)
            self.after(0, self.vars["Hostname"].set, name or "(no reverse DNS)")
        ok, latency = ping_host(IP)
        self.after(0, self.vars["Reachable"].set, (f"yes ({latency})" if ok else "no reply to ping"))

    def start_scan(self):
        if self.scanning or not IP:
            return
        self.scanning = True
        self.scan_btn.config(state="disabled")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Scanning common ports…")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        found = {"n": 0}

        def on_open(port):
            found["n"] += 1
            self.after(0, self._add_port, port)

        try:
            scan_ports(IP, on_open=on_open)
            msg = (f"Scan complete — {found['n']} open port(s)."
                   if found["n"] else "Scan complete — no common ports open.")
        except Exception as e:
            msg = f"Scan error: {e}"
        self.after(0, self._scan_done, msg)

    def _add_port(self, port):
        self.tree.insert("", "end", values=(port, "tcp", service_name(port) or "unknown"))

    def _scan_done(self, msg):
        self.scanning = False
        self.status_var.set(msg)
        self.scan_btn.config(state="normal")

    def _on_close(self):
        self.destroy()


if __name__ == "__main__":
    DeviceDetailUI().mainloop()
