"""
network_scanner_devices.py -- devices window for one network.

Can be opened two ways:

* In-process (fast path, no new program starts):
      import network_scanner_devices
      network_scanner_devices.open_devices(parent_window, essid, bssid, ch)
* Standalone, as its own process (kept for compatibility):
      python network_scanner_devices.py ESSID BSSID CH

Shows the devices the active backend can see for that network, and (where the
platform supports it) lets you disconnect one or all of them.
"""
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog

import netreg_ui as ui
import netreg_devicedb
import netreg_netsel
import netreg_report
from netreg_backend import get_backend

REFRESH_MS = 1000

_CENTER = {"PWR", "Packets", "Frames", "Notes"}


def open_devices(master, essid="", bssid="", ch=""):
    """Open the devices window in the current process as a child window. No new
    interpreter/Tk start-up, so it appears immediately."""
    win = DevicesUI(master, essid, bssid, ch)
    ui.raise_window(win, master)
    return win


class DevicesUI(tk.Toplevel):
    def __init__(self, master, essid="", bssid="", ch=""):
        super().__init__(master)
        self.backend = get_backend()
        self.caps = self.backend.capabilities()
        self.columns = self.backend.device_columns()
        # "Label" is a synthetic UI column shown first; the rest come from the
        # backend. Keep the backend column list separate so row dicts built from
        # it still map correctly.
        self.display_columns = ("Label",) + tuple(self.columns)
        self.target = {"ESSID": essid, "BSSID": bssid, "CH": ch}

        # Persistent per-device memory: custom labels + which MACs we've seen
        # before (so a brand-new device can be flagged when it joins).
        self.db = netreg_devicedb.DeviceDB()
        self._db_was_empty = (len(self.db) == 0)
        self._first_sweep = True
        self._new_macs = set()   # MACs flagged NEW this session (stay highlighted)

        # Be honest about what the device list actually scans: on macOS it
        # can only see the network this Mac is joined to, whatever row was
        # clicked. Prefer the backend's live connected SSID; fall back to the
        # name passed in (minus any "(connected)" marker).
        _suf = getattr(self.backend, "CONNECTED_SUFFIX", "") or ""
        _shown = netreg_netsel.strip_suffix(essid, _suf)
        try:
            _conn = (self.backend.connected_ssid() or "").strip()
        except Exception:
            _conn = ""
        self._net_label = _conn or _shown or "(network)"
        self.title(f"Devices on {self._net_label} ({self.backend.name})")
        self.geometry("1040x640")
        self.minsize(820, 480)
        self.scanning = False
        self._empty_iid = None

        ui.apply_theme(self)

        # --- header band ---------------------------------------------------
        head = ui.header(self, self._net_label or "Devices",
                         f"Devices on {self._net_label}, the Wi-Fi this "
                         f"computer is connected to — the only network LanLens "
                         f"can scan. Double-click one for details and open ports.")
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
        self.open_btn = ttk.Button(actions, text="Open device", style="Accent.TButton",
                                   command=self.open_selected_device)
        self.open_btn.pack(side="left")
        self.route_btn = ttk.Button(actions, text="Route via this Mac",
                                    command=self.route_selected)
        self.route_btn.pack(side="left", padx=(8, 0))
        self.cut_btn = ttk.Button(actions, text="Cut off internet",
                                  style="Danger.TButton", command=self.cut_selected)
        self.cut_btn.pack(side="left", padx=(8, 0))
        self.label_btn = ttk.Button(actions, text="Label device…",
                                    command=self.label_selected)
        self.label_btn.pack(side="left", padx=(8, 0))
        self.snapshot_btn = ttk.Button(actions, text="Save snapshot",
                                       command=self.save_snapshot)
        self.snapshot_btn.pack(side="left", padx=(8, 0))
        self.disc_btn = ttk.Button(actions, text="Disconnect Selected", style="Danger.TButton",
                                   command=self.disconnect_selected)
        self.disc_btn.pack(side="left", padx=(8, 0))

        try:
            import netreg_mitm
            self._can_route = netreg_mitm.available() and ("IP" in self.columns)
        except Exception:
            self._can_route = False
        # Gated features stay CLICKABLE but look locked, so clicking one explains
        # what's missing (via its command's messagebox) instead of doing nothing.
        if not self._can_route:
            self.route_btn.config(style="Locked.TButton", text="🔒 Route via this Mac")
            self.cut_btn.config(style="Locked.TButton", text="🔒 Cut off internet")
        if not self.caps.can_deauth:
            self.disc_btn.config(style="Locked.TButton", text="🔒 Disconnect Selected")

        # --- status line ---------------------------------------------------
        self.status = ui.StatusBar(self)
        self.status.pack(fill="x", padx=18, pady=(2, 8))
        self.status.set(self.caps.device_note or "Ready.", "idle")

        # --- table ---------------------------------------------------------
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 6))
        self.tree = ttk.Treeview(body, columns=self.display_columns,
                                 show="headings", height=18)
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        for col in self.display_columns:
            self.tree.heading(col, text=col)
            if col == "Label":
                self.tree.column(col, width=150, anchor="w", minwidth=90)
            elif col in ("IP", "Hostname", "Vendor"):
                self.tree.column(col, width=200, anchor="w", minwidth=120)
            elif col in ("MAC", "Station MAC"):
                self.tree.column(col, width=170, anchor="w", minwidth=140)
            elif col in _CENTER:
                self.tree.column(col, width=90, anchor="center")
            else:
                self.tree.column(col, width=150, anchor="w")
        ui.style_tree(self.tree)
        ui.enable_copy(self.tree)
        # A newly-joined (never-seen-before) device is highlighted until the
        # window is closed.
        self.tree.tag_configure("new", background="#6b5d1f", foreground="white")
        self.tree.bind("<Double-1>", self.on_double_click)
        self._show_empty("Press Start Scan to look for devices on this network.")

        # --- footer hint ---------------------------------------------------
        foot = ("Double-click a device for its details and open ports.   "
                "“Label device…” names a device (remembered across runs); a "
                "device joining for the first time is highlighted.")
        try:
            import netreg_mitm as _m
            if _m.available() and ("IP" in self.columns):
                foot += ("   “Route via this Mac” sends a selected device's "
                         "traffic through this computer; “Cut off internet” "
                         "intercepts it without forwarding, so the device loses "
                         "its connection (own-network use only).")
        except Exception:
            pass
        if not self.caps.can_deauth:
            foot += ("   The Disconnect button is locked (click it to see why): "
                     + self.caps.deauth_note)
        ttk.Label(self, text=foot, style="Muted.TLabel", wraplength=1000,
                  justify="left").pack(fill="x", padx=18, pady=(0, 14))

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(REFRESH_MS, self.refresh_table)

    # ----- empty-state helpers --------------------------------------------
    def _show_empty(self, text):
        if self.tree.get_children():
            return
        self._empty_iid = self.tree.insert("", "end",
                                           values=(text,) + ("",) * (len(self.display_columns) - 1))

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
        stays selected across scan ticks instead of flickering. Also prepends
        the custom label and flags brand-new devices."""
        self._clear_empty()
        seen = set()
        joined = []  # MACs newly joined this sweep (for the alert)
        for r in rows:
            key = self._row_key(r)
            if not key:
                continue
            iid = "dev:" + key
            seen.add(iid)
            mac = r.get("MAC") or r.get("Station MAC") or ""
            # New-device detection (persistent across runs). Suppress the alert
            # on the first sweep of a brand-new database (that's the baseline);
            # after that, anything not seen before is a real new joiner.
            was_known = self.db.is_known(mac) if mac else True
            if mac:
                self.db.mark_seen(mac)
            if mac and not was_known and not (self._db_was_empty and self._first_sweep):
                if mac not in self._new_macs:
                    self._new_macs.add(mac)
                    joined.append(mac)
            label = self.db.label(mac) if mac else ""
            values = (label,) + tuple(r.get(c, "") for c in self.columns)
            if self.tree.exists(iid):
                if self.tree.item(iid, "values") != values:
                    self.tree.item(iid, values=values)
            else:
                self.tree.insert("", "end", iid=iid, values=values)
        keep_sel = set(self.tree.selection())
        for iid in self.tree.get_children():
            if iid not in seen and iid not in keep_sel and iid != self._empty_iid:
                self.tree.delete(iid)
        self._restripe()
        self._first_sweep = False
        self.db.save()  # persist the baseline / newly-seen devices
        if joined:
            names = ", ".join(self.db.label(m) or m for m in joined)
            self.set_status(f"⚠ {len(joined)} new device(s) joined: {names}", "warn")
        if not self.tree.get_children():
            self._show_empty("No devices yet — still sweeping the network…")

    def _restripe(self):
        """Zebra-stripe rows and keep newly-joined devices highlighted. The
        'new' tag is applied last so its colour wins over the stripe."""
        for i, iid in enumerate(self.tree.get_children()):
            if iid == self._empty_iid:
                continue
            tags = ["even" if i % 2 else "odd"]
            mac = iid[4:] if iid.startswith("dev:") else ""
            if mac and mac in self._new_macs:
                tags.append("new")
            self.tree.item(iid, tags=tuple(tags))

    def on_double_click(self, _event=None):
        self.open_selected_device(quiet=True)

    def open_selected_device(self, quiet=False):
        """Open the details window for the selected device. Shared by the
        "Open device" button and a double-click. `quiet` suppresses the
        "pick a device" hint (used by the double-click path)."""
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            if not quiet:
                messagebox.showinfo(
                    "Pick a device",
                    "Select a device in the list first, then press “Open device”.")
            return
        row = dict(zip(self.display_columns, self.tree.item(sel[0], "values")))
        ip = row.get("IP", "")
        mac = row.get("MAC") or row.get("Station MAC") or ""
        hostname = row.get("Hostname", "")
        if not ip and not mac:
            if not quiet:
                messagebox.showinfo(
                    "Nothing to open",
                    "This row has no IP or MAC to inspect.")
            return
        self.set_status("Opening device details…", "work")
        # Open in-process so the window appears instantly. We do NOT fall back to
        # launching a separate python program: from a cloud-synced folder a
        # not-yet-downloaded file makes the import fail, and the separate program
        # fails the same way after a multi-second lag. open_child_window shows
        # the real error immediately instead of hanging.
        def _open():
            import device_detail
            return device_detail.open_detail(self, ip, mac, hostname)

        if ui.open_child_window(_open, "the device details window", parent=self) is None:
            self.set_status("Couldn't open device details — see the error.", "error")
        else:
            self.set_status("Opened device details.", "ok")

    def _selected_station(self):
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            return None
        vals = self.tree.item(sel[0], "values")
        row = dict(zip(self.display_columns, vals))
        return row.get("Station MAC") or row.get("MAC")

    def label_selected(self):
        """Give the selected device a custom name, remembered across runs."""
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            messagebox.showinfo("Pick a device",
                                "Select a device first to give it a label.")
            return
        row = dict(zip(self.display_columns, self.tree.item(sel[0], "values")))
        mac = row.get("MAC") or row.get("Station MAC") or ""
        if not netreg_devicedb.normalize_mac(mac):
            messagebox.showinfo(
                "No MAC",
                "This device has no MAC address to remember a label by.")
            return
        who = row.get("Hostname") or row.get("IP") or mac
        current = self.db.label(mac)
        new = simpledialog.askstring(
            "Label device",
            f"Name for {who}\n({mac}):",
            initialvalue=current, parent=self)
        if new is None:
            return  # cancelled
        self.db.set_label(mac, new)
        # reflect it immediately in the row
        iid = "dev:" + (row.get("MAC") or row.get("Station MAC") or row.get("IP") or "")
        if self.tree.exists(iid):
            vals = list(self.tree.item(iid, "values"))
            vals[0] = self.db.label(mac)
            self.tree.item(iid, values=vals)
        self.set_status(f"Labelled {mac} as “{self.db.label(mac) or '(cleared)'}”.", "ok")

    def save_snapshot(self):
        """Write the current device list (and this network) to a Markdown
        snapshot the user can keep for a baseline or diff later."""
        devices = []
        for iid in self.tree.get_children():
            if iid == self._empty_iid:
                continue
            row = dict(zip(self.display_columns, self.tree.item(iid, "values")))
            devices.append(row)
        essid = self.target.get("ESSID", "")
        networks = [dict(self.target)] if (essid or self.target.get("BSSID")) else []
        if not devices:
            messagebox.showinfo(
                "Nothing to save",
                "No devices in the list yet — run a scan first.")
            return
        text = netreg_report.build_report(
            networks=networks, devices=devices,
            meta={"network": essid})
        path = filedialog.asksaveasfilename(
            parent=self, title="Save network snapshot",
            defaultextension=".md",
            initialfile=netreg_report.default_filename(),
            filetypes=[("Markdown", "*.md"), ("All files", "*.*")])
        if not path:
            return
        try:
            netreg_report.save_report(text, path)
            self.set_status(f"Saved snapshot ({len(devices)} device(s)) to {path}", "ok")
            if messagebox.askyesno(
                    "Snapshot saved",
                    f"Saved a snapshot of {len(devices)} device(s) to:\n\n{path}\n\n"
                    "Reveal it in your file browser?"):
                self._reveal(path)
        except Exception as e:
            self.set_status(f"Couldn't save snapshot: {e}", "error")
            messagebox.showerror("Couldn't save snapshot",
                                 f"Writing the snapshot failed:\n\n{e}")

    @staticmethod
    def _reveal(path):
        """Show a saved file in the OS file browser (Finder/Explorer/file mgr)."""
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            elif sys.platform.startswith("win"):
                subprocess.Popen(["explorer", "/select,", path])
            else:
                import os
                subprocess.Popen(["xdg-open", os.path.dirname(path) or "."])
        except Exception:
            pass

    def route_selected(self):
        """Route the selected device's traffic through this Mac (and keep
        forwarding it, so the device still works)."""
        self._open_route(cut=False)

    def cut_selected(self):
        """Cut the selected device off: intercept its traffic but DON'T forward
        it to the router, so it loses its connection while staying on Wi-Fi."""
        self._open_route(cut=True)

    def _open_route(self, cut=False):
        what = "cut a device off" if cut else "route a device's traffic"
        if not getattr(self, "_can_route", False):
            try:
                import netreg_mitm
                have_bettercap = netreg_mitm.available()
            except Exception:
                have_bettercap = False
            if not have_bettercap:
                reason = ("This feature drives bettercap, which isn't installed.\n\n"
                          "Install it, then relaunch LanLens:\n"
                          "    brew install bettercap\n\n"
                          "(It also needs your admin password when you start, and "
                          "only works on a network you own.)")
            else:
                reason = ("This needs a device that has an IP address on this "
                          "network. The current list has no IP column to target.")
            messagebox.showinfo("Why this is locked", reason)
            return
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            messagebox.showinfo("Pick a device",
                                f"Select a device first to {what}.")
            return
        row = dict(zip(self.display_columns, self.tree.item(sel[0], "values")))
        ip = row.get("IP", "")
        if not ip:
            messagebox.showinfo("No IP", "This device has no IP to target.")
            return
        mac = row.get("MAC") or row.get("Station MAC") or ""
        host = row.get("Hostname", "")
        win_name = "cut-off" if cut else "route"
        self.set_status(f"Opening {win_name} window for {ip}…", "work")
        # Open in-process so it appears instantly, and show the real error at
        # once if it fails instead of launching a slow separate program that
        # would fail the same way from a cloud-synced folder.
        def _open():
            import mitm_window
            return mitm_window.open_route(self, ip, mac, host, cut=cut)

        if ui.open_child_window(_open, f"the {win_name} window", parent=self) is None:
            self.set_status(f"Couldn't open the {win_name} window — see the error.", "error")

    def disconnect_selected(self):
        if not self.caps.can_deauth:
            messagebox.showinfo("Why this is locked", self.caps.deauth_note)
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
    ESSID = sys.argv[1] if len(sys.argv) > 1 else ""
    BSSID = sys.argv[2] if len(sys.argv) > 2 else ""
    CH = sys.argv[3] if len(sys.argv) > 3 else ""
    root = tk.Tk()
    root.withdraw()  # the Toplevel below is the visible window
    win = DevicesUI(root, ESSID, BSSID, CH)
    win.protocol("WM_DELETE_WINDOW", lambda: (win._on_close(), root.destroy()))
    root.mainloop()
