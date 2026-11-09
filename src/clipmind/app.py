"""Wires capture, store, keys, search and the popup together.

Threads: the Win32 thread runs the hidden window (clipboard, hotkey, tray, session
events) and only queues events; the Tk main thread owns the index and the popup;
a short-lived worker thread runs the Windows Hello prompt and decryption.
"""

import logging
import logging.handlers
import queue
import threading
import time
import tkinter as tk

import numpy as np

from clipmind import config, keys, win32
from clipmind.capture import Capture
from clipmind.embed import Embedder
from clipmind.popup import Popup
from clipmind.search import Index
from clipmind.store import Store

log = logging.getLogger("clipmind")
OPEN, PAUSE, LOCK, WIPE, QUIT = 1, 2, 3, 4, 5


def setup_logging() -> None:
    handler = logging.handlers.RotatingFileHandler(config.data_dir() / "clipmind.log", maxBytes=1_000_000,
                                                   backupCount=1, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[handler])


class App:
    def __init__(self, cfg: dict, embedder: Embedder, store: Store, priv=None, sign=keys.hello_sign):
        self.cfg, self.embedder, self.store, self.sign = cfg, embedder, store, sign
        self.priv, self.index, self.unlocking = None, None, False
        self.events: queue.Queue = queue.Queue()
        self.capture = Capture(cfg, self._persist)
        self.last_used = time.monotonic()
        self.next_expire = time.monotonic() + 3600
        self.prev_hwnd = None
        self.root = tk.Tk()
        self.root.withdraw()
        self.popup = Popup(self.root, self)
        self.window = win32.Window(win32.parse_hotkey(cfg["hotkey"]), on_clipboard=self.capture.handle,
                                   on_hotkey=lambda: self.events.put(OPEN), on_lock=lambda: self.events.put(LOCK),
                                   on_menu=self._on_menu)
        if priv is not None:
            self._unlocked(priv, self.store.load(priv))

    # --- lifecycle -------------------------------------------------------------------------------------------

    def run(self) -> None:
        threading.Thread(target=self.window.run, name="win32", daemon=True).start()
        self.root.after(500, self._check_hotkey)
        self.root.after(50, self._pump)
        self.root.after(5000, self._tick)
        self.root.mainloop()

    def quit(self) -> None:
        self.capture.discard_pending()
        self.lock()
        self.window.stop()
        self.store.close()
        self.root.destroy()

    def _check_hotkey(self) -> None:
        if not self.window.hotkey_ok:
            log.warning("hotkey %s is taken by another app; open clipmind from the tray icon", self.cfg["hotkey"])

    def _pump(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if callable(event):
                    event()
                elif event == OPEN:
                    self.open()
                elif event == LOCK:
                    self.lock()
                elif event == WIPE:
                    self.wipe()
                elif event == QUIT:
                    self.quit()
                    return
        except queue.Empty:
            pass
        self.root.after(50, self._pump)

    def _tick(self) -> None:
        self.capture.flush()
        if self.index is not None and time.monotonic() - self.last_used > self.cfg["idle_lock_minutes"] * 60:
            log.info("idle lock")
            self.lock()
        if time.monotonic() > self.next_expire:
            self.next_expire = time.monotonic() + 3600
            self.store.expire()
        self.root.after(5000, self._tick)

    def _on_menu(self, cmd: int) -> None:  # runs on the Win32 thread
        if cmd == WIPE:
            if self.window.confirm("Delete ALL clipboard history and its keys?\n\nThis can't be undone."):
                self.events.put(WIPE)
        elif cmd == PAUSE:
            self.events.put(self.toggle_pause)
        else:
            self.events.put(cmd)

    # --- lock / unlock -------------------------------------------------------------------------------------------

    def open(self) -> None:
        if self.popup.visible():
            self.popup.hide()
            return
        self.prev_hwnd = win32.foreground_window()
        if self.index is not None:
            self.popup.show()
        elif not self.unlocking:
            self.unlocking = True  # the Hello prompt shows instead of the popup; the popup follows on success
            threading.Thread(target=self._unlock_worker, name="unlock", daemon=True).start()

    def _unlock_worker(self) -> None:
        try:
            priv = keys.unlock(self.sign)
            items = self.store.load(priv)
            self.events.put(lambda: self._unlocked(priv, items, show=True))
        except Exception as e:
            log.warning("unlock failed: %s", type(e).__name__)
            self.events.put(lambda: setattr(self, "unlocking", False))

    def _unlocked(self, priv, items, show: bool = False) -> None:
        self.priv, self.unlocking, self.index = priv, False, Index(self.embedder)
        dim = self.embedder.dim
        for item in sorted(items, key=lambda i: i.created_ms):
            emb = np.frombuffer(item.embedding, dtype=np.float16)
            vec = emb.astype(np.float32) if emb.size == dim else self.embedder.embed(item.text)  # model changed
            for old in self.index.add(item.id, item.text, item.created_ms, vec):
                self.store.delete(old)
        self.touch()
        log.info("unlocked items=%d", len(self.index))
        if show:
            self.popup.show()

    def lock(self) -> None:
        self.popup.hide()
        if self.index is not None:
            self.index.clear()
        self.index, self.priv = None, None

    def touch(self) -> None:
        self.last_used = time.monotonic()

    # --- actions ---------------------------------------------------------------------------------------------------

    def _persist(self, text: str) -> None:
        emb = self.embedder.embed(text)
        row = self.store.add(text, emb.astype(np.float16).tobytes())
        if self.index is not None:
            for old in self.index.add(row, text, int(time.time() * 1000), emb):
                self.store.delete(old)

    def search(self, query: str):
        return self.index.search(query, pending=self.capture.pending_texts()) if self.index is not None else []

    def paste(self, hit) -> None:
        self.touch()
        win32.set_text(hit.text, hwnd=self.window.hwnd, private=True)
        win32.paste_into(self.prev_hwnd)

    def delete(self, hit) -> None:
        if hit.id is None:
            self.capture.forget(hit.text)
        else:
            self.store.delete(hit.id)
            self.index.remove(hit.id)

    def toggle_pause(self) -> None:
        self.capture.paused = not self.capture.paused
        self.window.set_paused(self.capture.paused)
        log.info("capture %s", "paused" if self.capture.paused else "resumed")

    def status_text(self) -> str:
        state = "PAUSED (Ctrl+P resumes)" if self.capture.paused else "capturing"
        n = len(self.index) if self.index is not None else 0
        return f"{n} items · {state} · Enter paste · Shift+Del delete · Esc close"

    def wipe(self) -> None:
        self.capture.discard_pending()
        self.lock()
        self.store.wipe()
        keys.destroy()
        log.info("wiped history and keys")
        self.window.notify("History and keys are gone.\n\nclipmind will now quit. Start it again to set up new keys.")
        self.quit()


def run() -> int:
    if not win32.single_instance():
        print("clipmind is already running.")
        return 1
    win32.harden_process()
    win32.enable_dpi_awareness()
    setup_logging()
    cfg = config.load()
    for warning in win32.windows_history_warnings():
        log.warning("%s: it stores every copy, unfiltered. Turn it off in Settings > System > Clipboard.", warning)
    model = config.data_dir() / "models" / cfg["model"]
    if not (model / "model.safetensors").exists():
        print(f"Model not found in {model}.\nRun once: python scripts/fetch_model.py {cfg['model']}")
        return 1
    priv, public = None, keys.public_key()
    if public is None:
        priv = keys.setup()  # first run: Windows Hello prompt
        public = priv.public_key()
    store = Store(str(config.data_dir() / "history.db"), public, ttl_hours=cfg["ttl_days"] * 24,
                  max_items=cfg["max_items"])
    removed = store.expire()  # first thing, before capture or unlock
    log.info("start: expired=%d", removed)
    App(cfg, Embedder(model), store, priv=priv).run()
    return 0
