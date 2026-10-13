"""
network_scanner.py -- main window: scan Wi-Fi networks.

All OS-specific logic now lives in netreg_backend. This file is just the GUI:
it asks the active backend to scan and polls it for results. Double-clicking a
network opens the devices window for that network.
"""
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from netreg_backend import NETWORK_COLUMNS, get_backend

REFRESH_MS = 1500


class WifiNetworksUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.backend = get_backend()
        try:
            self.backend.prepare()
        except Exception:
            pass
        self.caps = self.backend.capabilities()

        self.title(f"NetworkRegulator -- Wi-Fi Networks ({self.backend.name})")
        self.geometry("1100x650")
        self.scanning = False

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        self.status_var = tk.StringVar(value=self.caps.scan_note or "Ready.")
        ttk.Label(top, textvariable=self.status_var).pack(side="left")

        self.start_btn = ttk.Button(top, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side="right")
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="right", padx=8)
        self.recover_btn = ttk.Button(top, text="Restore Wi-Fi", command=self.run_recovery)
        self.recover_btn.pack(side="right", padx=8)

        self.tree = ttk.Treeview(self, columns=NETWORK_COLUMNS, show="headings", height=22)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for col in NETWORK_COLUMNS:
            self.tree.heading(col, text=col)
            if col == "ESSID":
                self.tree.column(col, width=260, anchor="w")
            elif col == "BSSID":
                self.tree.column(col, width=170, anchor="w")
            elif col in ("Privacy", "Cipher", "Auth"):
                self.tree.column(col, width=110, anchor="w")
            elif col == "Band":
                self.tree.column(col, width=70, anchor="center")
            else:
                self.tree.column(col, width=80, anchor="center")
        self.tree.bind("<Double-1>", self.on_double_click)

        note = (f"Double-click a network to see its devices.  "
                f"Deauth on this machine: "
                f"{'available' if self.caps.can_deauth else 'unavailable'}.")
        ttk.Label(self, text=note, foreground="gray").pack(fill="x", padx=10, pady=(0, 10))

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(REFRESH_MS, self.refresh_table)

    def set_status(self, msg):
        self.status_var.set(msg)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def start_scan(self):
        if not self.caps.can_scan:
            messagebox.showinfo("Not available", self.caps.scan_note)
            return
        self.set_status("Starting scan...")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.scanning = True
        threading.Thread(target=self.backend.start_scan, daemon=True).start()

    def stop_scan(self):
        self.scanning = False
        self.set_status("Stopping...")
        threading.Thread(target=self.backend.stop_scan, daemon=True).start()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def refresh_table(self):
        if self.scanning:
            nets, note = self.backend.snapshot_networks()
            selected = None
            sel = self.tree.selection()
            if sel:
                vals = self.tree.item(sel[0], "values")
                if vals:
                    selected = vals[list(NETWORK_COLUMNS).index("BSSID")]
            self.clear_table()
            for n in nets[:200]:
                values = tuple(n.get(c, "") for c in NETWORK_COLUMNS)
                iid = self.tree.insert("", "end", values=values)
                if selected and n.get("BSSID") == selected:
                    self.tree.selection_set(iid)
            self.set_status(note)
        self.after(REFRESH_MS, self.refresh_table)

    def on_double_click(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        cols = list(NETWORK_COLUMNS)
        essid = vals[cols.index("ESSID")]
        bssid = vals[cols.index("BSSID")]
        ch = vals[cols.index("CH")]
        # Hand the target to the devices window as a separate process.
        subprocess.Popen([sys.executable, "network_scanner_devices.py", essid, bssid, ch])

    def run_recovery(self):
        if self.scanning:
            self.stop_scan()
        self.set_status("Restoring Wi-Fi...")

        def worker():
            ok, msg = self.backend.recover()
            self.after(0, self.set_status, msg)

        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self):
        try:
            self.scanning = False
            self.backend.stop_scan()
        finally:
            self.destroy()


if __name__ == "__main__":
    WifiNetworksUI().mainloop()
