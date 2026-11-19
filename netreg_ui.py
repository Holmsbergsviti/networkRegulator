"""
netreg_ui.py -- shared look & feel for every NetworkRegulator window.

One place to define the palette, fonts, spacing and widget styling so the
main window, the devices window, the device-detail window and the route
window all look like one app instead of four raw-tkinter dialogs.

Everything here is cosmetic. It never changes behaviour, and every step is
wrapped so that a platform which dislikes a particular style option falls
back to the default Tk look rather than failing to open the window.

Typical use in a window's __init__:

    import netreg_ui as ui
    ui.apply_theme(self)
    ui.header(self, "Wi-Fi Networks", "Networks your Mac can see right now")
    ...
    ui.style_tree(self.tree)          # zebra rows + comfortable height
    status = ui.StatusBar(self)        # colour-coded status line
    status.set("Ready.", "idle")
"""
import tkinter as tk
from tkinter import ttk
import tkinter.font as tkfont

# ---------------------------------------------------------------------------
# Palette -- a calm, modern light theme that reads well on macOS.
# ---------------------------------------------------------------------------
BG       = "#f4f5f7"   # window background
SURFACE  = "#ffffff"   # cards / tables
BORDER   = "#d9dce1"   # hairlines
INK      = "#1d2430"   # primary text
MUTED    = "#6b7280"   # secondary text / hints
ACCENT   = "#2f6fed"   # primary action / selection
ACCENT_D = "#2459c9"   # accent pressed
HEADER   = "#1d2430"   # header band
HEADER_T = "#ffffff"   # header text
STRIPE   = "#f7f8fa"   # alternate table row

# status colours
OK     = "#1f8a4c"
WORK   = "#2f6fed"
WARN   = "#b06a00"
DANGER = "#b4232a"
IDLE   = "#6b7280"

_STATE_COLORS = {
    "idle": IDLE, "ready": IDLE,
    "work": WORK, "working": WORK, "scan": WORK,
    "ok": OK, "done": OK,
    "warn": WARN,
    "error": DANGER, "danger": DANGER,
}


def fonts():
    """Return (base, bold, title, small, mono) Font objects, created once."""
    if getattr(fonts, "_cache", None):
        return fonts._cache
    base = tkfont.nametofont("TkDefaultFont")
    try:
        base.configure(size=13)
    except Exception:
        pass
    fam = base.actual("family")
    mk = lambda **kw: tkfont.Font(family=fam, **kw)
    cache = (
        base,
        mk(size=13, weight="bold"),
        mk(size=20, weight="bold"),
        mk(size=11),
        tkfont.Font(family="Menlo", size=11),
    )
    fonts._cache = cache
    return cache


def apply_theme(root):
    """Apply the shared theme to a Tk root/Toplevel. Safe to call once per
    top-level window."""
    base, bold, title, small, mono = fonts()
    try:
        root.configure(bg=BG)
    except Exception:
        pass
    style = ttk.Style(root)
    try:
        style.theme_use("clam")   # honours our colours on all platforms
    except Exception:
        pass

    try:
        style.configure(".", background=BG, foreground=INK, font=base)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=SURFACE)
        style.configure("Header.TFrame", background=HEADER)
        style.configure("TLabel", background=BG, foreground=INK, font=base)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=small)
        style.configure("CardMuted.TLabel", background=SURFACE, foreground=MUTED, font=small)
        style.configure("H1.TLabel", background=HEADER, foreground=HEADER_T, font=title)
        style.configure("Sub.TLabel", background=HEADER, foreground="#c3cad6", font=small)
        style.configure("Field.TLabel", background=SURFACE, foreground=MUTED, font=base)
        style.configure("Value.TLabel", background=SURFACE, foreground=INK, font=base)
        style.configure("TLabelframe", background=SURFACE, bordercolor=BORDER,
                        relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background=SURFACE, foreground=MUTED, font=bold)
        style.configure("TCheckbutton", background=BG, foreground=INK, font=base)
        style.map("TCheckbutton", background=[("active", BG)])

        # buttons --------------------------------------------------------
        style.configure("TButton", font=base, padding=(14, 7),
                        background=SURFACE, foreground=INK,
                        bordercolor=BORDER, focusthickness=0, relief="flat")
        style.map("TButton",
                  background=[("pressed", "#e9ebef"), ("active", "#eef0f3"),
                              ("disabled", "#f0f1f3")],
                  foreground=[("disabled", "#aeb4bd")])

        style.configure("Accent.TButton", font=bold, padding=(16, 7),
                        background=ACCENT, foreground="#ffffff",
                        bordercolor=ACCENT, relief="flat")
        style.map("Accent.TButton",
                  background=[("pressed", ACCENT_D), ("active", ACCENT_D),
                              ("disabled", "#b9c7ec")],
                  foreground=[("disabled", "#eef2fb")])

        style.configure("Danger.TButton", font=bold, padding=(14, 7),
                        background="#fbecec", foreground=DANGER, bordercolor="#eccccd",
                        relief="flat")
        style.map("Danger.TButton",
                  background=[("pressed", "#f3dadb"), ("active", "#f6e2e3"),
                              ("disabled", "#f5f0f0")],
                  foreground=[("disabled", "#d3a3a5")])

        # treeview -------------------------------------------------------
        style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE,
                        foreground=INK, rowheight=30, font=base,
                        bordercolor=BORDER, borderwidth=1, relief="solid")
        style.configure("Treeview.Heading", font=bold, foreground=MUTED,
                        background="#eef0f3", relief="flat", padding=(8, 8))
        style.map("Treeview.Heading", background=[("active", "#e4e7ec")])
        style.map("Treeview",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", "#ffffff")])
        style.configure("Vertical.TScrollbar", background="#e4e7ec",
                        troughcolor=BG, bordercolor=BG, arrowcolor=MUTED)
    except Exception:
        pass


def header(parent, title_text, subtitle=""):
    """A dark header band with an app title and optional subtitle.
    Returns the frame (so callers can drop controls into its right side)."""
    bar = ttk.Frame(parent, style="Header.TFrame", padding=(18, 14))
    bar.pack(fill="x", side="top")
    left = ttk.Frame(bar, style="Header.TFrame")
    left.pack(side="left", fill="x", expand=True)
    ttk.Label(left, text=title_text, style="H1.TLabel").pack(anchor="w")
    if subtitle:
        ttk.Label(left, text=subtitle, style="Sub.TLabel").pack(anchor="w", pady=(2, 0))
    return bar


def style_tree(tree):
    """Give a Treeview zebra striping. Call after inserting is set up; the
    striping is reapplied by restripe() whenever rows change."""
    try:
        tree.tag_configure("odd", background=SURFACE)
        tree.tag_configure("even", background=STRIPE)
    except Exception:
        pass


def restripe(tree):
    """Re-tag every row so the odd/even background pattern stays correct
    after inserts and deletes."""
    try:
        for i, iid in enumerate(tree.get_children()):
            tree.item(iid, tags=("even" if i % 2 else "odd",))
    except Exception:
        pass


class StatusBar(ttk.Frame):
    """A single-line status area with a coloured dot + message.

    state is one of: idle, work, ok, warn, error  (aliases accepted).
    """
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        base, bold, title, small, mono = fonts()
        self._dot = tk.Canvas(self, width=12, height=12, highlightthickness=0,
                              bg=BG, bd=0)
        self._dot.pack(side="left", padx=(0, 8))
        self._oval = self._dot.create_oval(2, 2, 11, 11, fill=IDLE, outline="")
        self._var = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self._var).pack(side="left")

    def set(self, msg, state="idle"):
        self._var.set(msg)
        color = _STATE_COLORS.get(state, IDLE)
        try:
            self._dot.itemconfigure(self._oval, fill=color)
        except Exception:
            pass

    # convenience so existing `status_var.set(...)`-style call sites are easy
    def set_text(self, msg):
        self._var.set(msg)
