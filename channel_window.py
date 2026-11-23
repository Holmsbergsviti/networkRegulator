"""
channel_window.py -- Wi-Fi channel analyzer window.

Opened from the main window's "Channel analyzer" button. It reads the networks
the scan has found and shows which channels are congested and which to switch
to. All the thinking is in netreg_channels.analyze(); this is just the view,
plus a Refresh that re-reads the current scan.
"""
import tkinter as tk
from tkinter import ttk

import netreg_ui as ui
import netreg_channels as ch


def open_channels(master, get_networks):
    """Open the analyzer in-process. `get_networks` is a no-arg callable that
    returns the current list of scanned-network dicts (so Refresh stays live)."""
    win = ChannelAnalyzerUI(master, get_networks)
    ui.raise_window(win, master)
    return win


class ChannelAnalyzerUI(tk.Toplevel):
    def __init__(self, master, get_networks):
        super().__init__(master)
        self._get_networks = get_networks
        self.title("Wi-Fi channel analyzer")
        self.geometry("560x620")
        self.minsize(480, 460)
        ui.apply_theme(self)

        ui.header(self, "Channel analyzer",
                  "Which channels are busy, and which to switch your router to.")

        self.rec = tk.Label(self, text="", bg="#1f5e2e", fg="white", justify="left",
                            anchor="w", wraplength=520, padx=14, pady=12,
                            font=("Helvetica", 13, "bold"))
        self.rec.pack(fill="x", padx=12, pady=(12, 8))

        # 2.4 GHz table: every channel 1..11 with occupants + congestion score.
        f24 = ttk.LabelFrame(self, text="2.4 GHz channels (1 / 6 / 11 don't overlap)")
        f24.pack(fill="x", padx=12, pady=(0, 8))
        self.t24 = ttk.Treeview(f24, columns=("ch", "nets", "load"),
                                show="headings", height=11)
        for c, text, w, a in (("ch", "Channel", 120, "center"),
                              ("nets", "Networks nearby", 180, "center"),
                              ("load", "Congestion", 180, "center")):
            self.t24.heading(c, text=text)
            self.t24.column(c, width=w, anchor=a)
        self.t24.pack(fill="x", padx=8, pady=6)
        self.t24.tag_configure("best", background="#1f5e2e", foreground="white")
        self.t24.tag_configure("pref", background="#eef0f3")

        # 5 GHz: channels actually in use.
        f5 = ttk.LabelFrame(self, text="5 GHz channels in use")
        f5.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.t5 = ttk.Treeview(f5, columns=("ch", "nets"), show="headings", height=6)
        for c, text, w in (("ch", "Channel", 160), ("nets", "Networks", 200)):
            self.t5.heading(c, text=text)
            self.t5.column(c, width=w, anchor="center")
        self.t5.pack(fill="both", expand=True, padx=8, pady=6)

        bar = ttk.Frame(self); bar.pack(fill="x", padx=12, pady=(0, 6))
        ttk.Button(bar, text="Refresh", style="Accent.TButton",
                   command=self.refresh).pack(side="left")
        self.note = tk.StringVar()
        ttk.Label(self, textvariable=self.note, style="Muted.TLabel",
                  wraplength=520, justify="left").pack(fill="x", padx=12, pady=(0, 10))

        self.refresh()

    def refresh(self):
        try:
            nets = list(self._get_networks() or [])
        except Exception:
            nets = []
        res = ch.analyze(nets)

        best24_ch, best24_reason = res["best_24"]
        rec_lines = [f"Best 2.4 GHz channel: {best24_ch}"]
        if res["best_5"]:
            rec_lines.append(f"Best 5 GHz channel: {res['best_5'][0]}")
        self.rec.config(text="  •  ".join(rec_lines))

        self.t24.delete(*self.t24.get_children())
        for channel, count, score in res["load_24"]:
            tags = []
            if channel == best24_ch:
                tags = ["best"]
            elif channel in ch.NON_OVERLAP_24:
                tags = ["pref"]
            self.t24.insert("", "end", tags=tuple(tags),
                            values=(channel, count, score if score else "clear"))

        self.t5.delete(*self.t5.get_children())
        if res["load_5"]:
            for channel, count in res["load_5"]:
                self.t5.insert("", "end", values=(channel, count))
        else:
            self.t5.insert("", "end", values=("—", "none seen"))

        if not nets:
            self.note.set("No scan results yet. Start a scan in the main window, "
                          "then press Refresh.")
        else:
            self.note.set(res["summary"] + "  Congestion weighs nearby networks by "
                          "signal strength and 2.4 GHz channel overlap; lower is better.")


if __name__ == "__main__":
    sample = [
        {"CH": "1", "Band": "2.4", "PWR": "-45"},
        {"CH": "1", "Band": "2.4", "PWR": "-60"},
        {"CH": "6", "Band": "2.4", "PWR": "-72"},
        {"CH": "11", "Band": "2.4", "PWR": "-50"},
        {"CH": "36", "Band": "5", "PWR": "-55"},
    ]
    root = tk.Tk(); root.withdraw()
    win = ChannelAnalyzerUI(root, lambda: sample)
    win.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
