"""
network_scanner_devices.py -- devices window for one network.

Launched by the main window as:  python network_scanner_devices.py ESSID BSSID CH
Shows the devices the active backend can see for that network, and (where the
platform supports it) lets you disconnect one or all of them.
"""
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import netreg_ui as ui
from netreg_backend import get_backend

REFRESH_MS = 1000

ESSID = sys.argv[1] if len(sys.argv) > 1 else ""
BSSID = sys.argv[2] if len(sys.argv) > 2 else ""
CH = sys.argv[3] if len(sys.argv) > 3 else ""

_CENTER = {"PWR", "Packets", "Frames", "Notes"}


class DevicesUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.backend = get_backend()
        self.caps = self.backend.capabilities()
        self.columns = self.backend.device_columns()
        self.target = {"ESSID": ESSID, "BSSID": BSSID, "CH": CH}

        self.title(f"Devices on {ESSID or '(network)'} ({self.backend.name})")
        self.geometry("1040x640")
        self.minsize(820, 480)
        self.scanning = False
        self._empty_iid = None

        ui.apply_theme(self)

        # --- header band ---------------------------------------------------
        head = ui.header(self, ESSID or "Devices",
                         "Devices seen on this network. Double-click one for details and open ports.")
        btns = ttk.Frame(head, style="Header.TFrame")
        btns.pack(side="right")
        self.start_btn = ttk.Button(btns, text="Start Scan", style="Accent.TButton",
                                    command=self.start_scan)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))

        # --- action row (operations on the selected device) ----------------
        actions = ttk.Frame(self)
        actions.pack(fill="x", padx=18, pady=(14, 6))
        self.route_btn = ttk.Button(actions, text="Route via this Mac",
                                    command=self.route_selected)
        self.route_btn.pack(side="left")
        self.disc_btn = ttk.Button(actions, text="Disconnect Selected", style="Danger.TButton",
                                   command=self.disconnect_selected)
        self.disc_btn.pack(side="left", padx=(8, 0))

        try:
            import netreg_mitm
            self._can_route = netreg_mitm.available() and ("IP" in self.columns)
        except Exception:
            self._can_route = False
        if not self._can_route:
            self.route_btn.config(state="disabled")
        if not self.caps.can_deauth:
            self.disc_btn.config(state="disabled")

        # --- status line ---------------------------------------------------
        self.status = ui.StatusBar(self)
        self.status.pack(fill="x", padx=18, pady=(2, 8))
        self.status.set(self.caps.device_note or "Ready.", "idle")

        # --- table ---------------------------------------------------------
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 6))
        self.tree = ttk.Treeview(body, columns=self.columns, show="headings", height=18)
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        for col in self.columns:
            self.tree.heading(col, text=col)
            if col in ("IP", "Hostname", "Vendor"):
                self.tree.column(col, width=220, anchor="w", minwidth=120)
            elif col in ("MAC", "Station MAC"):
                self.tree.column(col, width=180, anchor="w", minwidth=140)
            elif col in _CENTER:
                self.tree.column(col, width=90, anchor="center")
            else:
                self.tree.column(col, width=160, anchor="w")
        ui.style_tree(self.tree)
        self.tree.bind("<Double-1>", self.on_double_click)
        self._show_empty("Press Start Scan to look for devices on this network.")

        # --- footer hint ---------------------------------------------------
        foot = "Double-click a device for its details and open ports."
        try:
            import netreg_mitm as _m
            if _m.available() and ("IP" in self.columns):
                foot += ("   “Route via this Mac” sends a selected device's "
                         "traffic through this computer (own-network use only).")
        except Exception:
            pass
        if not self.caps.can_deauth:
            foot += "   The Disconnect button is off: " + self.caps.deauth_note
        ttk.Label(self, text=foot, style="Muted.TLabel", wraplength=1000,
                  justify="left").pack(fill="x", padx=18, pady=(0, 14))

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(REFRESH_MS, self.refresh_table)

    # ----- empty-state helpers --------------------------------------------
    def _show_empty(self, text):
        if self.tree.get_children():
            return
        self._empty_iid = self.tree.insert("", "end",
                                           values=(text,) + ("",) * (len(self.columns) - 1))

    def _clear_empty(self):
        if self._empty_iid and self.tree.exists(self._empty_iid):
            self.tree.delete(self._empty_iid)
        self._empty_iid = None

    def set_status(self, msg, state="work"):
        self.status.set(msg, state)

    def start_scan(self):
        if not self.caps.can_list_devices:
            messagebox.showinfo("Not available", self.caps.device_note)
            return
        self._clear_empty()
        self.set_status("Scanning for devices…", "work")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.scanning = True
        threading.Thread(target=lambda: self.backend.start_devices(self.target), daemon=True).start()

    def stop_scan(self):
        self.scanning = False
        self.set_status("Stopping…", "work")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

        def worker():
            self.backend.stop_devices()
            self.after(0, lambda: self.set_status("Stopped. Scan not running.", "idle"))

        threading.Thread(target=worker, daemon=True).start()

    def refresh_table(self):
        if self.scanning:
            rows, note = self.backend.snapshot_devices()
            self._merge_rows(rows[:200])
            self.set_status(note, "work")
        self.after(REFRESH_MS, self.refresh_table)

    def _row_key(self, row):
        return row.get("MAC") or row.get("Station MAC") or row.get("IP") or ""

    def _merge_rows(self, rows):
        """Update rows in place, keyed by MAC (or IP), so the selected device
        stays selected across scan ticks instead of flickering."""
        self._clear_empty()
        seen = set()
        for r in rows:
            key = self._row_key(r)
            if not key:
                continue
            iid = "dev:" + key
            seen.add(iid)
            values = tuple(r.get(c, "") for c in self.columns)
            if self.tree.exists(iid):
                if self.tree.item(iid, "values") != values:
                    self.tree.item(iid, values=values)
            else:
                self.tree.insert("", "end", iid=iid, values=values)
        keep_sel = set(self.tree.selection())
        for iid in self.tree.get_children():
            if iid not in seen and iid not in keep_sel and iid != self._empty_iid:
                self.tree.delete(iid)
        ui.restripe(self.tree)
        if not self.tree.get_children():
            self._show_empty("No devices yet — still sweeping the network…")

    def on_double_click(self, _event=None):
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            return
        row = dict(zip(self.columns, self.tree.item(sel[0], "values")))
        ip = row.get("IP", "")
        mac = row.get("MAC") or row.get("Station MAC") or ""
        hostname = row.get("Hostname", "")
        if not ip and not mac:
            return
        self.set_status("Opening device details…", "work")
        # Open in-process so the window appears instantly. Spawning a fresh
        # python process (the old behaviour) cost a noticeable lag on macOS,
        # especially from a cloud-synced folder. Fall back to a subprocess if
        # anything about the in-process path fails.
        try:
            import device_detail
            device_detail.open_detail(self, ip, mac, hostname)
        except Exception:
            subprocess.Popen([sys.executable, "device_detail.py", ip, mac, hostname])

    def _selected_station(self):
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            return None
        vals = self.tree.item(sel[0], "values")
        row = dict(zip(self.columns, vals))
        return row.get("Station MAC") or row.get("MAC")

    def route_selected(self):
        if not getattr(self, "_can_route", False):
            messagebox.showinfo(
                "Not available",
                "Routing traffic through this machine needs bettercap "
                "(install it with: brew install bettercap) and a device with "
                "an IP address.")
            return
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            messagebox.showinfo("Pick a device",
                                "Select a device first to route its traffic "
                                "through this Mac.")
            return
        row = dict(zip(self.columns, self.tree.item(sel[0], "values")))
        ip = row.get("IP", "")
        if not ip:
            messagebox.showinfo("No IP", "This device has no IP to target.")
            return
        mac = row.get("MAC") or row.get("Station MAC") or ""
        host = row.get("Hostname", "")
        subprocess.Popen([sys.executable, "mitm_window.py", ip, mac, host])

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
            self.after(0, lambda: self.set_status(msg, "ok" if ok else "error"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self):
        try:
            self.scanning = False
            self.backend.stop_devices()
        finally:
            self.destroy()


if __name__ == "__main__":
    DevicesUI().mainloop()
