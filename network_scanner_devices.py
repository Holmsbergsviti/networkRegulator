"""
network_scanner_devices.py -- devices window for one network.

Launched by the main window as:  python network_scanner_devices.py ESSID BSSID CH
Shows the devices the active backend can see for that network, and (where the
platform supports it) lets you disconnect one or all of them.
"""
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from netreg_backend import get_backend

REFRESH_MS = 2000

ESSID = sys.argv[1] if len(sys.argv) > 1 else ""
BSSID = sys.argv[2] if len(sys.argv) > 2 else ""
CH = sys.argv[3] if len(sys.argv) > 3 else ""


class DevicesUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.backend = get_backend()
        self.caps = self.backend.capabilities()
        self.columns = self.backend.device_columns()
        self.target = {"ESSID": ESSID, "BSSID": BSSID, "CH": CH}

        self.title(f"Devices on {ESSID or '(network)'} ({self.backend.name})")
        self.geometry("1000x600")
        self.scanning = False

        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)
        self.status_var = tk.StringVar(value=self.caps.device_note or "Ready.")
        ttk.Label(top, textvariable=self.status_var).pack(side="left")

        self.start_btn = ttk.Button(top, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side="right")
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="right", padx=8)
        self.disc_btn = ttk.Button(top, text="Disconnect Selected", command=self.disconnect_selected)
        self.disc_btn.pack(side="right", padx=16)
        if not self.caps.can_deauth:
            self.disc_btn.config(state="disabled")

        self.tree = ttk.Treeview(self, columns=self.columns, show="headings", height=20)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200, anchor="w")

        foot = self.caps.device_note
        if not self.caps.can_deauth:
            foot += "  The Disconnect button is off: " + self.caps.deauth_note
        ttk.Label(self, text=foot, foreground="gray", wraplength=960,
                  justify="left").pack(fill="x", padx=10, pady=(0, 10))

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(REFRESH_MS, self.refresh_table)

    def set_status(self, msg):
        self.status_var.set(msg)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def start_scan(self):
        if not self.caps.can_list_devices:
            messagebox.showinfo("Not available", self.caps.device_note)
            return
        self.set_status("Scanning for devices...")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.scanning = True
        threading.Thread(target=lambda: self.backend.start_devices(self.target), daemon=True).start()

    def stop_scan(self):
        self.scanning = False
        threading.Thread(target=self.backend.stop_devices, daemon=True).start()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.set_status("Stopped.")

    def refresh_table(self):
        if self.scanning:
            rows, note = self.backend.snapshot_devices()
            self.clear_table()
            for r in rows[:200]:
                self.tree.insert("", "end", values=tuple(r.get(c, "") for c in self.columns))
            self.set_status(note)
        self.after(REFRESH_MS, self.refresh_table)

    def _selected_station(self):
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0], "values")
        row = dict(zip(self.columns, vals))
        # station MAC is called different things per backend
        return row.get("Station MAC") or row.get("MAC")

    def disconnect_selected(self):
        if not self.caps.can_deauth:
            messagebox.showinfo("Not available", self.caps.deauth_note)
            return
        station = self._selected_station()
        bssid = self.target.get("BSSID", "")
        if not station:
            if not messagebox.askyesno("Disconnect all",
                                       "No device selected. Disconnect everyone on this network?"):
                return

        def worker():
            ok, msg = self.backend.deauth(bssid, station)
            self.after(0, self.set_status, msg)

        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self):
        try:
            self.scanning = False
            self.backend.stop_devices()
        finally:
            self.destroy()


if __name__ == "__main__":
    DevicesUI().mainloop()
