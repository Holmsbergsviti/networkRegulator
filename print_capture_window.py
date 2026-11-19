"""
print_capture_window.py -- see whether your print jobs are sent in the clear.

Launched by the device-detail window ("Inspect print traffic"), or directly:
    python print_capture_window.py PRINTER_IP [NAME]

====================  OWN-NETWORK / AUTHORIZED USE ONLY  ====================
This captures traffic between this computer and the printer so you can check
whether the data you print is encrypted. Use it ONLY on a printer/network you
own or are explicitly authorized to test. Start stays disabled until you
confirm below.
============================================================================

How to read it: tick the box, press Start, then print a test page or a
document from this Mac. The capture watches the print ports (raw/9100, IPP/631,
LPD/515, and IPPS/443) and tells you whether what left your machine was
plaintext (readable by anyone sniffing the LAN) or TLS-encrypted.
"""
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

import netreg_printcap as pcap
from netreg_traffic import human_bytes

# verdict -> (banner background, short title)
_VERDICT_STYLE = {
    "plaintext": ("#7a1f1f", "PLAINTEXT — readable!"),
    "encrypted": ("#1f5e2e", "Encrypted (TLS)"),
    "opaque": ("#6b5d1f", "Captured, not plainly readable"),
    "no_traffic": ("#333944", "Waiting for a print job…"),
}


def open_capture(master, ip="", name=""):
    """Open the print-capture window in the current process as a child window,
    so it appears immediately instead of starting a separate program."""
    win = PrintCaptureUI(master, ip, name)
    try:
        win.lift()
        win.focus_force()
    except Exception:
        pass
    return win


class PrintCaptureUI(tk.Toplevel):
    def __init__(self, master, ip="", name=""):
        super().__init__(master)
        self.ip = ip or ""
        self.name = name or ""
        who = self.name or self.ip or "(no target)"
        self.title(f"Inspect print traffic — {who}")
        self.geometry("660x720")
        self.session = pcap.PrintCaptureSession()
        self.busy = False
        self._polling = False

        banner = tk.Label(
            self,
            text=("OWN-NETWORK / AUTHORIZED USE ONLY\n"
                  "This captures the traffic between this Mac and the printer to "
                  "check whether your print jobs are encrypted. Only do this on a "
                  "printer and network you own or are explicitly allowed to test."),
            bg="#7a1f1f", fg="white", justify="left", wraplength=560, padx=12, pady=10,
        )
        banner.pack(fill="x")

        info = ttk.LabelFrame(self, text="Printer")
        info.pack(fill="x", padx=12, pady=(12, 8))
        for label, val in (("Name", self.name or "—"), ("IP", self.ip or "(unknown)")):
            row = ttk.Frame(info); row.pack(fill="x", padx=10, pady=2)
            ttk.Label(row, text=label + ":", width=10, anchor="w").pack(side="left")
            ttk.Label(row, text=val, anchor="w").pack(side="left")

        ttk.Label(
            self,
            text=("Tip: this reads THIS Mac's own print jobs — no spoofing needed, "
                  "because the packets start here. (To inspect another device's "
                  "jobs to the printer, use \"Route via this Mac\" first.)"),
            foreground="gray", wraplength=600, justify="left",
        ).pack(fill="x", padx=12, pady=(0, 4))

        self.authorized = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self, variable=self.authorized, command=self._sync_buttons,
            text="I own this printer/network or am explicitly authorized to test it.",
        ).pack(anchor="w", padx=14, pady=(4, 2))

        bar = ttk.Frame(self); bar.pack(fill="x", padx=12, pady=8)
        self.start_btn = ttk.Button(bar, text="Start capture", command=self.start,
                                    state="disabled")
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=10)

        self.status_var = tk.StringVar()
        ttk.Label(self, textvariable=self.status_var, wraplength=600,
                  justify="left", foreground="gray").pack(fill="x", padx=12, pady=(2, 6))

        # --- verdict banner ------------------------------------------------ #
        self.verdict_lbl = tk.Label(
            self, text="Verdict will appear here once you print something.",
            bg="#333944", fg="white", justify="left", wraplength=600,
            padx=14, pady=14, font=("Helvetica", 13, "bold"))
        self.verdict_lbl.pack(fill="x", padx=12, pady=(4, 8))

        # --- per-port table ------------------------------------------------ #
        ports = ttk.LabelFrame(self, text="Printer connections seen")
        ports.pack(fill="x", padx=12, pady=(0, 8))
        cols = ("port", "state", "packets", "data")
        self.tree = ttk.Treeview(ports, columns=cols, show="headings", height=5)
        for c, text, w, anchor in (
            ("port", "Protocol / port", 300, "w"),
            ("state", "Content", 160, "w"),
            ("packets", "Packets", 80, "e"),
            ("data", "Data", 90, "e"),
        ):
            self.tree.heading(c, text=text)
            self.tree.column(c, width=w, anchor=anchor)
        self.tree.pack(fill="x", padx=8, pady=6)

        # --- recovered content --------------------------------------------- #
        detail = ttk.LabelFrame(self, text="What leaked (plaintext jobs only)")
        detail.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.detail_text = tk.Text(detail, height=8, wrap="word", state="disabled",
                                   font=("Menlo", 11), background="#111317",
                                   foreground="#d6dde6")
        self.detail_text.pack(fill="both", expand=True, padx=8, pady=6)

        ttk.Label(
            self,
            text=("Plaintext means anyone who can see the LAN traffic could read "
                  "what you printed. Encrypted (IPPS/TLS) means they'd see only "
                  "that a job happened, not its contents."),
            foreground="gray", wraplength=600, justify="left",
        ).pack(fill="x", padx=12, pady=(0, 8))

        ready, msg = pcap.preflight()
        self._ready = ready and bool(self.ip)
        if not self.ip:
            self.status_var.set("No printer IP was passed — nothing to capture.")
        elif not ready:
            self.status_var.set(msg)
        else:
            self.status_var.set("Tick the box above to enable Start.")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ----------------------------------------------------------------- UI --- #
    def _set_verdict(self, res):
        bg, _title = _VERDICT_STYLE.get(res["verdict"], ("#333944", ""))
        self.verdict_lbl.config(text=res["headline"], bg=bg)

        self.tree.delete(*self.tree.get_children())
        state_words = {"plaintext": "readable (plaintext)", "encrypted": "TLS-encrypted",
                       "opaque": "binary / not readable", "empty": "no payload"}
        for r in res["ports"]:
            self.tree.insert("", "end", values=(
                r["label"], state_words.get(r["state"], r["state"]),
                r["packets"], human_bytes(r["bytes"])))

        lines = []
        if res["job_names"]:
            lines.append("Document / job name(s): " + ", ".join(res["job_names"]))
        if res["markers"]:
            lines.append("Detected: " + ", ".join(res["markers"]))
        if res["excerpt"]:
            lines.append("")
            lines.append("Readable snippet from the job:")
            lines.append(res["excerpt"])
        if not lines:
            if res["verdict"] == "encrypted":
                lines = ["Nothing readable — the job is encrypted. Good."]
            elif res["verdict"] == "no_traffic":
                lines = ["Nothing captured yet. Print a test page to the printer."]
            else:
                lines = ["No plaintext document content was recovered."]
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", "\n".join(lines))
        self.detail_text.config(state="disabled")

    def _start_polling(self):
        self._polling = True
        self.after(800, self._poll)

    def _stop_polling(self):
        self._polling = False

    def _poll(self):
        if not self._polling:
            return

        def work():
            res = self.session.analyze(self.ip)
            self.after(0, lambda: self._set_verdict(res))
        threading.Thread(target=work, daemon=True).start()
        self.after(1200, self._poll)

    def _sync_buttons(self):
        running = self.session.is_running()
        can_start = self._ready and self.authorized.get() and not running and not self.busy
        self.start_btn.config(state="normal" if can_start else "disabled")
        self.stop_btn.config(state="normal" if running and not self.busy else "disabled")

    def start(self):
        if not messagebox.askyesno(
            "Confirm",
            f"Capture traffic between this Mac and the printer at {self.ip}?\n\n"
            "Only proceed on a printer/network you own or are authorized to test."):
            return
        self.busy = True
        self._sync_buttons()
        self.status_var.set("Starting… you may be asked for your password.")

        def worker():
            ok, msg = self.session.start(self.ip)
            def done():
                self.busy = False
                self.status_var.set(msg)
                if ok:
                    self._start_polling()
                self._sync_buttons()
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def stop(self):
        self._stop_polling()
        self.busy = True
        self._sync_buttons()
        self.status_var.set("Stopping the capture…")

        def worker():
            ok, msg = self.session.stop()
            res = self.session.analyze(self.ip)
            def done():
                self.busy = False
                self.status_var.set(msg)
                self._set_verdict(res)  # final verdict after stop
                self._sync_buttons()
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def _on_close(self):
        self._stop_polling()
        try:
            if self.session.is_running():
                self.session.stop()
        finally:
            self.destroy()


if __name__ == "__main__":
    IP = sys.argv[1] if len(sys.argv) > 1 else ""
    NAME = sys.argv[2] if len(sys.argv) > 2 else ""
    root = tk.Tk()
    root.withdraw()  # the Toplevel below is the visible window
    win = PrintCaptureUI(root, IP, NAME)
    win.protocol("WM_DELETE_WINDOW", lambda: (win._on_close(), root.destroy()))
    root.mainloop()
