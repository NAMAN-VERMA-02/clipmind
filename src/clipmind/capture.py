"""Capture policy: decide, for each clipboard change, whether it may be kept.

Checks run cheapest and least intrusive first; the text is read only after every
metadata check passed. Kept clips wait in RAM for `quarantine_seconds` before they
are persisted: password managers (including browser extensions, whose copies carry
no sensitive-format flag) clear the clipboard after a few seconds, and a clear
during the quarantine discards the clip before it ever reaches disk.

Logs carry decisions and lengths only, never clip text.
"""

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from clipmind import filters

log = logging.getLogger(__name__)


@dataclass
class Pending:
    text: str
    seen: float


class Capture:
    def __init__(self, cfg: dict, persist: Callable[[str], None], clock: Callable[[], float] = time.monotonic):
        self.cfg, self.persist, self.clock = cfg, persist, clock
        self.paused = False
        self.pid = os.getpid()
        self.pending: list[Pending] = []
        self._lock = threading.Lock()
        self._blocked_apps = set(cfg["blocked_apps"])
        self._private = [m.lower() for m in cfg["private_title_markers"]]
        self._banking = [k.lower() for k in cfg["blocked_title_keywords"]]

    def handle(self, snap) -> str:
        """Process one clipboard change. Returns the decision (for logs and tests)."""
        try:
            decision, length = self._decide(snap)
        except Exception as e:  # never log str(e): exception text can carry clipboard bytes
            decision, length = f"error:{type(e).__name__}", 0
        log.info("clip %s len=%d", decision, length)
        return decision

    def _decide(self, snap) -> tuple[str, int]:
        if self.paused:
            return "paused", 0
        if snap.owner_pid() == self.pid:
            return "own_write", 0
        if snap.sensitive_format():
            return "sensitive_format", 0
        if not snap.has_text():
            return self._cleared(), 0
        owner = snap.owner_exe()
        fg_exe, title = snap.foreground()
        if owner in self._blocked_apps or fg_exe in self._blocked_apps:
            return "blocked_app", 0
        title = title.lower()
        if any(m in title for m in self._private):
            return "private_window", 0
        if any(k in title for k in self._banking):
            return "banking_window", 0
        text = snap.read_text(self.cfg["max_chars"] + 1)
        if text is None or not text.strip():
            return self._cleared(), 0
        if len(text) > self.cfg["max_chars"]:
            return "too_big", len(text)
        reason = filters.check(text)
        if reason:
            return f"secret:{reason}", len(text)
        with self._lock:
            self.pending = [p for p in self.pending if p.text != text]  # same text again: refresh it
            self.pending.append(Pending(text, self.clock()))
        return "kept", len(text)

    def _cleared(self) -> str:
        """An emptied clipboard right after a copy is the auto-clear of a password manager: forget that copy."""
        with self._lock:
            if self.pending:
                self.pending.pop()
                return "cleared:discarded_pending"
        return "cleared"

    def flush(self, force_all: bool = False) -> int:
        """Persist clips whose quarantine is over. Call periodically."""
        cutoff = self.clock() - self.cfg["quarantine_seconds"]
        with self._lock:
            due = [p for p in self.pending if force_all or p.seen <= cutoff]
            self.pending = [p for p in self.pending if p not in due]
        for p in due:
            try:
                self.persist(p.text)
            except Exception as e:
                log.error("persist failed: %s", type(e).__name__)
        return len(due)

    def discard_pending(self) -> None:
        """On exit: clips still in quarantine are dropped, not persisted (privacy over 2 minutes of history)."""
        with self._lock:
            self.pending.clear()

    def forget(self, text: str) -> None:
        with self._lock:
            self.pending = [p for p in self.pending if p.text != text]

    def pending_texts(self) -> list[str]:
        with self._lock:
            return [p.text for p in self.pending]
