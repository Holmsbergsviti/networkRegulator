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

import netreg_ui as ui
from netreg_backend import NETWORK_COLUMNS, get_backend
import netreg_netsel
import netreg_rogue

REFRESH_MS = 1500

# Columns whose values are short / numeric and read better centred.
_CENTER = {"PWR", "CH", "Band", "Beacons", "IV"}
_NUMERIC_SORT = {"PWR", "CH", "Beacons", "IV"}


class WifiNetworksUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.backend = get_backend()
        try:
            self.backend.prepare()
        except Exception:
            pass
        self.caps = self.backend.capabilities()

        self.title(f"LanLens — Wi-Fi Networks ({self.backend.name})")
        self.geometry("1120x680")
        self.minsize(900, 520)
        self.scanning = False
        self._sort_state = {}

        ui.apply_theme(self)

        # --- header band ---------------------------------------------------
        head = ui.header(self, "Wi-Fi Networks",
                         "Scan the networks around you. Double-click one to see its devices.")
        btns = ttk.Frame(head, style="Header.TFrame")
        btns.pack(side="right")
        self.start_btn = ttk.Button(btns, text="Start Scan", style="Accent.TButton",
                                    command=self.start_scan)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_scan,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))
        self.channels_btn = ttk.Button(btns, text="Channel analyzer",
                                       command=self.open_channel_analyzer)
        self.channels_btn.pack(side="left", padx=(8, 0))
        self.rogue_btn = ttk.Button(btns, text="Rogue-AP check",
                                    command=self.run_rogue_check)
        self.rogue_btn.pack(side="left", padx=(8, 0))
        self.speed_btn = ttk.Button(btns, text="Speed test",
                                     command=self.run_speed_test)
        self.speed_btn.pack(side="left", padx=(8, 0))
        self.recover_btn = ttk.Button(btns, text="Restore Wi-Fi", command=self.run_recovery)
        self.recover_btn.pack(side="left", padx=(8, 0))

        # --- status line ---------------------------------------------------
        self.status = ui.StatusBar(self)
        self.status.pack(fill="x", padx=18, pady=(12, 8))
        self.status.set(self.caps.scan_note or "Ready to scan.", "idle")

        # --- action row (operates on the selected network) -----------------
        acts = ttk.Frame(self)
        acts.pack(fill="x", padx=18, pady=(0, 6))
        self.view_btn = ttk.Button(acts, text="View devices", style="Accent.TButton",
                                   command=self.open_selected_devices)
        self.view_btn.pack(side="left")
        ttk.Label(acts, text="Select a network above, then “View devices” "
                  "(or double-click it).", style="Muted.TLabel").pack(
                      side="left", padx=(10, 0))

        # --- table ---------------------------------------------------------
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 6))
        self.tree = ttk.Treeview(body, columns=NETWORK_COLUMNS, show="headings", height=22)
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        for col in NETWORK_COLUMNS:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_by(c))
            if col == "ESSID":
                self.tree.column(col, width=280, anchor="w", minwidth=160)
            elif col == "BSSID":
                self.tree.column(col, width=180, anchor="w", minwidth=140)
            elif col in ("Privacy", "Cipher", "Auth"):
                self.tree.column(col, width=100, anchor="center")
            elif col in _CENTER:
                self.tree.column(col, width=72, anchor="center")
            else:
                self.tree.column(col, width=80, anchor="center")
        ui.style_tree(self.tree)
        ui.enable_copy(self.tree)
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_net_select)

        # Empty-state hint shown inside the (otherwise blank) table.
        self._empty_iid = None
        self._show_empty("Press Start Scan to look for Wi-Fi networks.")

        # --- footer hint ---------------------------------------------------
        if self.caps.can_deauth:
            deauth_line = "Disconnecting devices is ready on this machine."
        else:
            deauth_line = "Disconnecting devices isn't available here. " + self.caps.deauth_note
        ttk.Label(self, text="Double-click a network to see its devices.   " + deauth_line,
                  style="Muted.TLabel", wraplength=1060, justify="left").pack(
                      fill="x", padx=18, pady=(0, 14))

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(REFRESH_MS, self.refresh_table)

        # Make the main window actually come to the front on launch. Without
        # this, Tk opens the window but never orders it front or activates the
        # app, so on macOS it can appear behind whatever is already frontmost
        # (and if another app is in full-screen, on a different Space entirely).
        self.after(0, self._bring_to_front)

    def _bring_to_front(self):
        """Lift + focus the window so it doesn't hide behind other windows."""
        try:
            self.update_idletasks()
            self.deiconify()
            self.lift()
            # Briefly pin topmost, then release, to pull it in front once.
            self.attributes("-topmost", True)
            self.after(400, lambda: self.attributes("-topmost", False))
            self.focus_force()
        except Exception:
            pass

    # ----- empty-state helpers --------------------------------------------
    def _show_empty(self, text):
        if self.tree.get_children():
            return
        self._empty_iid = self.tree.insert("", "end", values=(text,) + ("",) * (len(NETWORK_COLUMNS) - 1))

    def _clear_empty(self):
        if self._empty_iid and self.tree.exists(self._empty_iid):
            self.tree.delete(self._empty_iid)
        self._empty_iid = None

    def set_status(self, msg, state="work"):
        self.status.set(msg, state)

    def start_scan(self):
        if not self.caps.can_scan:
            messagebox.showinfo("Not available", self.caps.scan_note)
            return
        self._clear_empty()
        self.set_status("Starting scan…", "work")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.scanning = True
        threading.Thread(target=self.backend.start_scan, daemon=True).start()

    def stop_scan(self):
        self.scanning = False
        self.set_status("Stopping…", "work")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

        def worker():
            self.backend.stop_scan()
            self.after(0, lambda: self.set_status("Stopped. Scan not running.", "idle"))

        threading.Thread(target=worker, daemon=True).start()

    def refresh_table(self):
        if self.scanning:
            nets, note = self.backend.snapshot_networks()
            self._merge_rows(nets[:200])
            self.set_status(note, "work")
        self.after(REFRESH_MS, self.refresh_table)

    def _merge_rows(self, nets):
        """Update the table in place so a user's selection survives each scan
        tick (the table used to be cleared and rebuilt, which dropped the
        selection and made rows flicker). Rows are keyed by BSSID."""
        self._clear_empty()
        cols = list(NETWORK_COLUMNS)
        seen = set()
        for n in nets:
            bssid = n.get("BSSID", "")
            if not bssid:
                continue
            iid = "net:" + bssid
            seen.add(iid)
            values = tuple(n.get(c, "") for c in cols)
            if self.tree.exists(iid):
                if self.tree.item(iid, "values") != values:
                    self.tree.item(iid, values=values)
            else:
                self.tree.insert("", "end", iid=iid, values=values)
        # drop networks that have disappeared, but never the current selection
        keep_sel = set(self.tree.selection())
        for iid in self.tree.get_children():
            if iid not in seen and iid not in keep_sel and iid != self._empty_iid:
                self.tree.delete(iid)
        ui.restripe(self.tree)
        if not self.tree.get_children():
            self._show_empty("No networks yet — still listening…")

    def _sort_by(self, col):
        if self._empty_iid:
            return
        reverse = self._sort_state.get(col, False)
        rows = [(self.tree.set(iid, col), iid) for iid in self.tree.get_children()]
        if col in _NUMERIC_SORT:
            def key(pair):
                try:
                    return (0, float(pair[0]))
                except (ValueError, TypeError):
                    return (1, 0.0)
        else:
            key = lambda pair: pair[0].lower()
        rows.sort(key=key, reverse=reverse)
        for i, (_, iid) in enumerate(rows):
            self.tree.move(iid, "", i)
        self._sort_state[col] = not reverse
        ui.restripe(self.tree)

    def on_double_click(self, _event=None):
        self.open_selected_devices()

    def _connected_suffix(self) -> str:
        return getattr(self.backend, "CONNECTED_SUFFIX", "") or ""

    def _is_connected_essid(self, essid_value) -> bool:
        return netreg_netsel.is_connected_row(essid_value, self._connected_suffix())

    def _connected_name(self) -> str:
        """Plain name of the network this Mac is joined to: from the backend
        if it knows, else from the suffix-marked row in the table."""
        try:
            n = (self.backend.connected_ssid() or "").strip()
        except Exception:
            n = ""
        if n:
            return n
        suf = self._connected_suffix()
        if suf:
            idx = list(NETWORK_COLUMNS).index("ESSID")
            for iid in self.tree.get_children():
                if iid == self._empty_iid:
                    continue
                val = self.tree.item(iid, "values")[idx]
                if netreg_netsel.is_connected_row(val, suf):
                    return netreg_netsel.strip_suffix(val, suf)
        return ""

    def _on_net_select(self, _event=None):
        # When we can tell which network this Mac is joined to, only allow
        # "View devices" on that row: the device list can only scan the
        # connected network, so offering it for another SSID is misleading.
        suf = self._connected_suffix()
        if not suf:
            self.view_btn.state(["!disabled"])
            return
        sel = self.tree.selection()
        idx = list(NETWORK_COLUMNS).index("ESSID")
        ok = bool(sel) and sel[0] != self._empty_iid and self._is_connected_essid(
            self.tree.item(sel[0], "values")[idx])
        self.view_btn.state(["!disabled"] if ok else ["disabled"])

    def open_selected_devices(self):
        """Open the devices window for the selected network. Shared by the
        "View devices" button and a double-click on the row."""
        sel = self.tree.selection()
        if not sel or sel[0] == self._empty_iid:
            messagebox.showinfo(
                "Pick a network",
                "Select a network in the list first, then press “View devices”.")
            return
        vals = self.tree.item(sel[0], "values")
        cols = list(NETWORK_COLUMNS)
        essid = vals[cols.index("ESSID")]
        bssid = vals[cols.index("BSSID")]
        ch = vals[cols.index("CH")]
        suf = self._connected_suffix()
        if suf and not self._is_connected_essid(essid):
            conn = self._connected_name() or "the network this Mac is joined to"
            messagebox.showinfo(
                "Connect to this network first",
                f"LanLens can only list the devices on the Wi-Fi this Mac is "
                f"actually connected to ({conn}).\n\n"
                f"“{essid}” isn't that network, so its devices can't be seen "
                f"from here. Connect your Mac to it first, then open its "
                f"devices.")
            return
        essid = netreg_netsel.strip_suffix(essid, suf)  # drop "(connected)" marker
        self.set_status(f"Opening devices on {essid or 'network'}…", "work")
        # Open the devices window in-process so it appears instantly. We do NOT
        # fall back to launching a separate Python program: from a cloud-synced
        # folder a not-yet-downloaded file makes the import fail, and the
        # separate program fails the same way after a multi-second delay — which
        # is what made a click feel like it hung. open_child_window surfaces the
        # real error immediately instead.
        def _open():
            import network_scanner_devices
            return network_scanner_devices.open_devices(self, essid, bssid, ch)

        if ui.open_child_window(_open, "the devices window", parent=self) is None:
            self.set_status("Couldn't open the devices window — see the error.", "error")

    def run_rogue_check(self):
        """Flag evil-twin / rogue-AP patterns in the networks currently
        scanned (same name both secured and open; one name on several BSSIDs)."""
        nets = self._current_networks()
        if not nets:
            messagebox.showinfo("Rogue-AP check",
                                "No networks scanned yet — press Start Scan first.")
            return
        alerts = netreg_rogue.analyze(nets)
        if not alerts:
            messagebox.showinfo(
                "Rogue-AP check",
                f"Nothing suspicious across {len(nets)} network(s): no name is "
                f"both secured and open, and no duplicate access points stand "
                f"out.\n\n(On macOS other networks' BSSIDs are hidden, so the "
                f"duplicate-AP check has less to work with there.)")
            self.set_status("Rogue-AP check: nothing suspicious.", "ok")
            return
        messagebox.showwarning(
            "Rogue-AP check — take a look",
            "\n\n".join(f"\u2022 {a}" for a in alerts))
        self.set_status(f"Rogue-AP check: {len(alerts)} thing(s) to review.", "warn")

    def _current_networks(self):
        """The networks currently in the table, as dicts the channel analyzer
        can read. Reads straight from the table so it reflects the live scan."""
        cols = list(NETWORK_COLUMNS)
        out = []
        for iid in self.tree.get_children():
            if iid == self._empty_iid:
                continue
            vals = self.tree.item(iid, "values")
            out.append(dict(zip(cols, vals)))
        return out

    def open_channel_analyzer(self):
        self.set_status("Opening channel analyzer…", "work")

        def _open():
            import channel_window
            return channel_window.open_channels(self, self._current_networks)

        if ui.open_child_window(_open, "the channel analyzer", parent=self) is None:
            self.set_status("Couldn't open the channel analyzer — see the error.", "error")

    def run_speed_test(self):
        """Measure this computer's own internet link (latency / download /
        upload) in the background. Progress shows in the status line; the final
        result also pops up in a dialog so it can't be missed."""
        self.speed_btn.config(state="disabled")
        self.set_status("Starting speed test…", "work")

        def worker():
            import netreg_speedtest
            res = netreg_speedtest.run_speedtest(
                progress=lambda m: self.after(0, lambda m=m: self.set_status(m, "work")))

            def done():
                self.set_status(res.describe(), "ok" if res.ok else "error")
                self.speed_btn.config(state="normal")
                if res.ok:
                    messagebox.showinfo(
                        "Speed test result",
                        f"Your connection:\n\n"
                        f"Download:  {netreg_speedtest.mbps(res.download_bps):.1f} Mbps\n"
                        f"Upload:    {netreg_speedtest.mbps(res.upload_bps):.1f} Mbps\n"
                        f"Ping:      {res.latency_ms:.0f} ms  (jitter ±{res.jitter_ms:.0f} ms)",
                        parent=self)
                else:
                    messagebox.showerror(
                        "Speed test failed",
                        f"The speed test couldn't complete:\n\n{res.error or 'unknown error'}",
                        parent=self)

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def run_recovery(self):
        if self.scanning:
            self.stop_scan()
        self.set_status("Restoring Wi-Fi…", "work")

        def worker():
            ok, msg = self.backend.recover()
            self.after(0, lambda: self.set_status(msg, "ok" if ok else "error"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self):
        try:
            self.scanning = False
            self.backend.stop_scan()
        finally:
            self.destroy()


if __name__ == "__main__":
    WifiNetworksUI().mainloop()
