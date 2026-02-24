import os
import time
import csv
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import sys

REFRESH_MS = 1500
CAPTURE_PREFIX = "device_scan"          # produces scan-01.csv
CAPTURE_CSV = f"{CAPTURE_PREFIX}-01.csv"
bssid = sys.argv[1]
ch = sys.argv[2]
file_name = sys.argv[3]
mon_interface = sys.argv[4]

subprocess.run(["sudo", "airodump-ng", "--bssid", bssid, "-c", ch, "-w", file_name, mon_interface])


def parse_airodump_csv(path: str):
    """
    Parse airodump CSV and return list of dicts (networks).
    Only parses the first section (APs) until the 'Station MAC' section begins.
    """
    if not os.path.exists(path):
        return []

    networks = []
    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            in_ap_section = True

            for row in reader:
                if not row:
                    continue

                # When station section starts, stop reading AP section
                if row[0].strip() == "Station MAC":
                    in_ap_section = False

                if not in_ap_section:
                    break

                # Skip headers
                if row[0].strip() == "BSSID":
                    continue

                # AP rows have at least ESSID at index 13 in standard airodump CSV
                if len(row) < 14:
                    continue

                bssid = row[0].strip()
                channel = row[3].strip()
                privacy = row[5].strip()
                cipher_ = row[6].strip()
                auth = row[7].strip()
                power = row[8].strip()
                beacons = row[9].strip()
                iv = row[10].strip()
                essid = row[13].strip()

                def channel_to_band(ch_str: str) -> str:
                    try:
                        ch = int(ch_str)
                    except Exception:
                        return "?"
                    # 1–14 usually 2.4 GHz; 36+ usually 5 GHz (simplified)
                    return "2.4" if 1 <= ch <= 14 else ("5" if ch >= 36 else "?")

                # Basic sanity: BSSID looks like MAC
                if len(bssid.split(":")) != 6:
                    continue

                networks.append({
                    "BSSID": bssid,
                    "CH": channel,
                    "Band": channel_to_band(channel),
                    "PWR": power,
                    "Privacy": privacy,
                    "Cipher": cipher_,
                    "Auth": auth,
                    "Beacons": beacons,
                    "IV": iv,
                    "ESSID": essid,
                })

    except Exception:
        return []

    # Sort: strongest signal (PWR is usually negative; -30 stronger than -90)
    def pwr_key(n):
        try:
            return int(n["PWR"])
        except Exception:
            return -999

    networks.sort(key=pwr_key, reverse=True)
    return networks


class WifiNetworksUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wi-Fi Networks Scanner")
        self.geometry("1100x650")

        self.proc = None
        self.worker = None
        self.scanning = False

        # Table
        columns = ("ESSID", "PWR", "CH", "Band", "Privacy", "Cipher", "Auth", "BSSID", "Beacons", "IV")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=22)
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        for col in columns:
            self.tree.heading(col, text=col)
            # column widths
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

        self.after(REFRESH_MS, self.refresh_table)

    def on_double_click(self, _event=None):
        """
        sel = self.tree.selection()
        if not sel:
            return

        vals = self.tree.item(sel[0], "values")
        # columns: ESSID, PWR, CH, Band, Privacy, Cipher, Auth, BSSID, ...
        ch = vals[2]
        bssid = vals[7]

        # choose a filename prefix (you can customize)
        file_name = f"capture_{bssid.replace(':','')}_ch{ch}"

        cmd = f"sudo airodump-ng -d {bssid} -c {ch} -w {file_name} {mon_interface}"

        # Copy to clipboard
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self.set_status("Copied command to clipboard (paste in terminal).")
        """

    def set_status(self, msg: str):
        self.status_var.set(msg)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _scan_finished_ui(self):
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self.scanning:
            self.set_status("Stopped.")
        else:
            self.set_status("Ready.")
        self.scanning = False

    def stop_scan(self):
        self.scanning = False
        self.set_status("Stopping...")
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.proc = None

    def refresh_table(self):
        # Update table periodically while scanning
        if self.scanning:
            nets = parse_airodump_csv(CAPTURE_CSV)

            # Preserve selection BSSID if user clicked a row
            selected = None
            sel = self.tree.selection()
            if sel:
                selected_vals = self.tree.item(sel[0], "values")
                if len(selected_vals) >= 7:
                    selected = selected_vals[6]  # BSSID column

            self.clear_table()

            best_count = 0
            for n in nets:
                values = (
                    n["ESSID"],
                    n["PWR"],
                    n["CH"],
                    n["Band"],
                    n["Privacy"],
                    n["Cipher"],
                    n["Auth"],
                    n["BSSID"],
                    n["Beacons"],
                    n["IV"],
                )
                iid = self.tree.insert("", "end", values=values)
                if selected and n["BSSID"] == selected:
                    self.tree.selection_set(iid)

                best_count += 1
                if best_count >= 200:  # avoid huge UI lag
                    break

            self.set_status(f"Scanning... Networks found: {len(nets)} (showing up to 200)")

        self.after(REFRESH_MS, self.refresh_table)

if __name__ == "__main__":
    app = WifiNetworksUI()
    app.mainloop()