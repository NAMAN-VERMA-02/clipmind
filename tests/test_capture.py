import logging
import os

import pytest

from clipmind import config
from clipmind.capture import Capture


class FakeSnap:
    def __init__(self, text="hello world", owner_pid=1234, owner_exe="notepad.exe", fg=("notepad.exe", "Untitled"),
                 sensitive=None):
        self.text, self._pid, self._exe, self._fg, self._sensitive = text, owner_pid, owner_exe, fg, sensitive
        self.reads = 0

    def owner_pid(self):
        return self._pid

    def owner_exe(self):
        return self._exe

    def foreground(self):
        return self._fg

    def sensitive_format(self):
        return self._sensitive

    def has_text(self):
        return self.text is not None

    def read_text(self, limit):
        self.reads += 1
        return None if self.text is None else self.text[:limit]


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def setup():
    stored, clock = [], Clock()
    return Capture(config.load(config.Path(os.devnull)), stored.append, clock), stored, clock


def test_plain_text_is_kept_then_persisted_after_quarantine(setup):
    cap, stored, clock = setup
    assert cap.handle(FakeSnap("meeting at 5")) == "kept"
    assert cap.flush() == 0 and stored == []
    clock.t += 121
    assert cap.flush() == 1 and stored == ["meeting at 5"]


def test_paused_reads_nothing(setup):
    cap, _, _ = setup
    cap.paused = True
    snap = FakeSnap()
    assert cap.handle(snap) == "paused" and snap.reads == 0


def test_own_writes_are_ignored(setup):
    cap, _, _ = setup
    assert cap.handle(FakeSnap(owner_pid=os.getpid())) == "own_write"


@pytest.mark.parametrize("fmt", ["ExcludeClipboardContentFromMonitorProcessing", "Clipboard Viewer Ignore",
                                 "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"])
def test_password_manager_formats_drop_without_reading_text(setup, fmt):
    cap, _, _ = setup
    snap = FakeSnap("hunter2", sensitive=fmt)
    assert cap.handle(snap) == "sensitive_format" and snap.reads == 0


@pytest.mark.parametrize("snap", [FakeSnap(owner_exe="keepassxc.exe"), FakeSnap(owner_exe="bitwarden.exe"),
                                  FakeSnap(owner_exe=None, fg=("1password.exe", "1Password")),
                                  FakeSnap(owner_exe="phoneexperiencehost.exe")])
def test_blocked_apps_drop_without_reading_text(setup, snap):
    cap, _, _ = setup
    assert cap.handle(snap) == "blocked_app" and snap.reads == 0


@pytest.mark.parametrize("title", ["New InPrivate tab - Microsoft Edge", "Google - Google Chrome (Incognito)",
                                   "Mozilla Firefox Private Browsing"])
def test_private_windows_drop(setup, title):
    cap, _, _ = setup
    snap = FakeSnap(owner_exe="msedge.exe", fg=("msedge.exe", title))
    assert cap.handle(snap) == "private_window" and snap.reads == 0


def test_banking_title_drops(setup):
    cap, _, _ = setup
    assert cap.handle(FakeSnap(fg=("chrome.exe", "HDFC Bank NetBanking - Google Chrome"))) == "banking_window"


def test_too_big_is_dropped(setup):
    cap, _, _ = setup
    assert cap.handle(FakeSnap("x" * 40_000)) == "too_big"


def test_secret_is_dropped(setup):
    cap, stored, clock = setup
    assert cap.handle(FakeSnap("4111 1111 1111 1111")) == "secret:card"
    clock.t += 500
    cap.flush()
    assert stored == []


def test_auto_clear_discards_the_pending_copy(setup):
    """Bitwarden-style: copy from a browser extension (no flags), extension clears the clipboard 10 s later."""
    cap, stored, clock = setup
    cap.handle(FakeSnap("note one"))
    cap.handle(FakeSnap("correct horse battery staple", owner_exe="chrome.exe", fg=("chrome.exe", "Vault")))
    clock.t += 10
    assert cap.handle(FakeSnap(None, owner_exe="chrome.exe")) == "cleared:discarded_pending"
    clock.t += 200
    cap.flush()
    assert stored == ["note one"]


def test_clear_to_empty_string_also_counts(setup):
    cap, _, _ = setup
    cap.handle(FakeSnap("pa55phrase words"))
    assert cap.handle(FakeSnap("")) == "cleared:discarded_pending" and cap.pending_texts() == []


def test_same_text_again_is_deduplicated(setup):
    cap, _, _ = setup
    cap.handle(FakeSnap("a"))
    cap.handle(FakeSnap("b"))
    cap.handle(FakeSnap("a"))
    assert cap.pending_texts() == ["b", "a"]


def test_exit_discards_quarantine(setup):
    cap, stored, _ = setup
    cap.handle(FakeSnap("x"))
    cap.discard_pending()
    cap.flush(force_all=True)
    assert stored == []


def test_errors_are_contained_and_logged_without_text(setup, caplog):
    cap, _, _ = setup

    class Broken(FakeSnap):
        def read_text(self, limit):
            raise UnicodeDecodeError("utf-16", b"SECRETBYTES", 0, 1, "bad")

    with caplog.at_level(logging.DEBUG):
        assert cap.handle(Broken()) == "error:UnicodeDecodeError"
    assert "SECRETBYTES" not in caplog.text


def test_logs_never_contain_clip_text(setup, caplog):
    cap, _, clock = setup
    samples = ["4111 1111 1111 1111", "Your OTP is 482913", "password = 'Tr0ub4dor&3'", "meeting notes for monday",
               "AKIA" + "Q" * 16, "plain words here"]
    with caplog.at_level(logging.DEBUG):
        for s in samples:
            cap.handle(FakeSnap(s))
        clock.t += 500
        cap.flush()
    for s in samples:
        assert s not in caplog.text


def test_config_lists_extend_defaults_and_bad_values_are_ignored(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"blocked_apps": ["MyVault.exe"], "ttl_days": -3, "hotkey": 5, "unknown": 1}')
    cfg = config.load(path)
    assert "myvault.exe" in cfg["blocked_apps"] and "keepassxc.exe" in cfg["blocked_apps"]
    assert cfg["ttl_days"] == 7 and cfg["hotkey"] == "win+alt+v"
