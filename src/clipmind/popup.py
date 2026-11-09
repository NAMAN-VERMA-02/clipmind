"""The search popup (tkinter). Keyboard only: type, Up/Down, Enter pastes, Shift+Del deletes, Esc closes."""

import time
import tkinter as tk
from tkinter import font as tkfont

from clipmind import win32

BG, FG, MUTED, ACCENT, FIELD = "#1f1f23", "#ececf1", "#9a9aa6", "#3b6fd8", "#2a2a30"
WIDTH, ROWS = 680, 12


def _ago(created_ms: int) -> str:
    s = max(0, int(time.time() - created_ms / 1000))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= size:
            return f"{s // size}{unit}"
    return "now"


def _one_line(text: str, width: int = 88) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= width else flat[: width - 1] + "…"


class Popup:
    """`app` provides: search(query) -> hits, paste(hit), delete(hit), toggle_pause(), touch(), status_text()."""

    def __init__(self, root: tk.Tk, app):
        self.app, self.hits, self._pending_search = app, [], None
        self.win = tk.Toplevel(root, bg=BG)
        self.win.withdraw()
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        base = tkfont.Font(family="Segoe UI", size=11)
        self.query = tk.Entry(self.win, font=tkfont.Font(family="Segoe UI", size=13), bg=FIELD, fg=FG,
                              insertbackground=FG, relief="flat", highlightthickness=1,
                              highlightbackground=FIELD, highlightcolor=ACCENT)
        self.query.pack(fill="x", padx=10, pady=(10, 6), ipady=6)
        self.results = tk.Listbox(self.win, font=base, bg=BG, fg=FG, selectbackground=ACCENT, selectforeground=FG,
                                  activestyle="none", relief="flat", highlightthickness=0, height=ROWS,
                                  exportselection=False)
        self.results.pack(fill="both", expand=True, padx=10)
        self.status = tk.Label(self.win, font=tkfont.Font(family="Segoe UI", size=9), bg=BG, fg=MUTED, anchor="w")
        self.status.pack(fill="x", padx=10, pady=(4, 8))
        self.query.bind("<KeyRelease>", self._on_type)
        for key, fn in (("<Down>", lambda e: self._move(1)), ("<Up>", lambda e: self._move(-1)),
                        ("<Return>", lambda e: self._choose()), ("<Escape>", lambda e: self.hide()),
                        ("<Shift-Delete>", lambda e: self._delete()), ("<Control-p>", lambda e: self._pause())):
            self.query.bind(key, fn)
        self.results.bind("<Double-Button-1>", lambda e: self._choose())
        self.win.bind("<FocusOut>", lambda e: self.win.after(150, self._hide_if_unfocused))

    def visible(self) -> bool:
        return self.win.state() == "normal"

    def show(self) -> None:
        left, top, right, bottom = win32.work_area_at_cursor()
        height = self.win.winfo_reqheight()
        self.win.geometry(f"{WIDTH}x{height}+{left + (right - left - WIDTH) // 2}+{top + (bottom - top) // 5}")
        self.query.delete(0, "end")
        self.win.deiconify()
        self.win.lift()
        self.win.focus_force()
        self.query.focus_set()
        self.refresh()

    def hide(self) -> None:
        self.win.withdraw()
        self.results.delete(0, "end")  # don't keep clip text in widgets while hidden
        self.hits = []

    def refresh(self) -> None:
        self.app.touch()
        self.hits = self.app.search(self.query.get())
        self.results.delete(0, "end")
        for hit in self.hits:
            self.results.insert("end", f"{_one_line(hit.text)}    · {_ago(hit.created_ms)}")
        if self.hits:
            self.results.selection_set(0)
        self.status.config(text=self.app.status_text())

    def _on_type(self, event) -> None:
        if event.keysym in ("Up", "Down", "Return", "Escape"):
            return
        if self._pending_search:
            self.win.after_cancel(self._pending_search)
        self._pending_search = self.win.after(60, self.refresh)

    def _move(self, step: int) -> str:
        if self.hits:
            cur = (self.results.curselection() or (0,))[0]
            new = max(0, min(len(self.hits) - 1, cur + step))
            self.results.selection_clear(0, "end")
            self.results.selection_set(new)
            self.results.see(new)
        return "break"

    def _selected(self):
        sel = self.results.curselection()
        return self.hits[sel[0]] if sel and sel[0] < len(self.hits) else None

    def _choose(self) -> None:
        hit = self._selected()
        self.hide()
        if hit:
            self.app.paste(hit)

    def _delete(self) -> str:
        hit = self._selected()
        if hit:
            self.app.delete(hit)
            self.refresh()
        return "break"

    def _pause(self) -> str:
        self.app.toggle_pause()
        self.status.config(text=self.app.status_text())
        return "break"

    def _hide_if_unfocused(self) -> None:
        if self.visible() and self.win.focus_get() is None:
            self.hide()
