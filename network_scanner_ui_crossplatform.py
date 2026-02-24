import os
import time
import csv
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# --------- SETTINGS ----------
INTERFACE = "wlp0s20f3"
MON_INTERFACE = INTERFACE + "mon"

CAPTURE_PREFIX = "scan"          # produces scan-01.csv
CAPTURE_CSV = f"{CAPTURE_PREFIX}-01.csv"

REFRESH_MS = 1500                # table refresh interval

RECOVERY_SCRIPT = "recovery.py"  # your file in same folder
# -----------------------------


def run_quiet(cmd: list[str]) -> int:
    """Run command without spamming UI; return exit code."""
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode
    except Exception:
        return 1


def interface_exists(name: str) -> bool:
    try:
        # more reliable than string search in "ip a"
        r = subprocess.run(["ip", "link", "show", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False


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
        self.title("Wi-Fi Networks (airodump CSV → Table)")
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

        self.recover_btn = ttk.Button(top, text="Run Recovery", command=self.run_recovery)
        self.recover_btn.pack(side="right", padx=8)

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

        # Bottom help
        note = (
            "Tip: Run this UI with sudo so it doesn't block on password prompts:\n"
            "  sudo python3 wifi_networks_table_ui.py\n"
            "The table updates from scan-01.csv while airodump runs."
        )
        ttk.Label(self, text=note, foreground="gray").pack(fill="x", padx=10, pady=(0, 10))

        self.after(REFRESH_MS, self.refresh_table)

    def on_double_click(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return

        vals = self.tree.item(sel[0], "values")
        # columns: ESSID, PWR, CH, Band, Privacy, Cipher, Auth, BSSID, ...
        ch = vals[2]
        bssid = vals[7]

        # choose a filename prefix (you can customize)
        file_name = f"capture_{bssid.replace(':','')}_ch{ch}"

        cmd = f"sudo airodump-ng -d {bssid} -c {ch} -w {file_name} {MON_INTERFACE}"

        # Copy to clipboard
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self.set_status("Copied command to clipboard (paste in terminal).")

    def set_status(self, msg: str):
        self.status_var.set(msg)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Running", "Scan is already running.")
            return

        if not interface_exists(INTERFACE):
            messagebox.showerror("Interface not found", f"Interface does not exist: {INTERFACE}")
            return

        self.clear_table()
        self.set_status("Starting monitor mode + capture...")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.scanning = True

        self.worker = threading.Thread(target=self._scan_worker, daemon=True)
        self.worker.start()

    def _scan_worker(self):
        try:
            # Clean old captures (optional)
            for suffix in ("-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.cap"):
                p = CAPTURE_PREFIX + suffix
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass

            # 1) Kill processes that interfere
            self.after(0, self.set_status, "airmon-ng check kill ...")
            run_quiet(["sudo", "airmon-ng", "check", "kill"])

            # 2) Start monitor mode
            self.after(0, self.set_status, f"airmon-ng start {INTERFACE} ...")
            run_quiet(["sudo", "airmon-ng", "start", INTERFACE])

            # 3) Start airodump writing CSV
            self.after(0, self.set_status, "airodump-ng running (writing CSV)...")
            self.proc = subprocess.Popen(
                ["sudo", "airodump-ng", MON_INTERFACE, "-w", CAPTURE_PREFIX, "--output-format", "csv"],
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

    def run_recovery(self):
        # stop scan first
        if self.scanning:
            self.stop_scan()

        if not os.path.exists(RECOVERY_SCRIPT):
            messagebox.showerror("Missing file", f"Couldn't find {RECOVERY_SCRIPT} in this folder.")
            return

        self.set_status("Running recovery.py ...")
        try:
            # Run recovery in a separate thread so UI doesn't freeze
            def worker():
                # If recovery needs sudo, you can change this to ["sudo", "python3", RECOVERY_SCRIPT]
                subprocess.run(["python3", RECOVERY_SCRIPT])
                self.after(0, self.set_status, "Recovery finished.")

            threading.Thread(target=worker, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Recovery error", str(e))
            self.set_status("Recovery error.")


if __name__ == "__main__":
    app = WifiNetworksUI()
    app.mainloop()