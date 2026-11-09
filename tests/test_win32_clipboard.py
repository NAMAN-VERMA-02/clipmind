"""Against the real Windows clipboard. Saves and restores the text on it."""

import pytest

from clipmind import win32

pytestmark = pytest.mark.win32


@pytest.fixture
def clipboard():
    snap = win32.Snapshot()
    try:
        before = snap.read_text(1_000_000) if snap.has_text() else None
    except win32.ClipboardBusy:
        pytest.skip("no clipboard access in this session")
    yield snap
    if before is not None:
        win32.set_text(before, private=True)


def test_plain_text_roundtrip(clipboard):
    win32.set_text("clipmind plain ✓", private=False)
    assert clipboard.sensitive_format() is None
    assert clipboard.read_text(100) == "clipmind plain ✓"


def test_private_write_is_flagged_for_monitors(clipboard):
    win32.set_text("clipmind private", private=True)
    assert clipboard.sensitive_format() == "ExcludeClipboardContentFromMonitorProcessing"


def test_can_include_in_history_zero_is_detected(clipboard):
    with win32._Open():
        win32.user32.EmptyClipboard()
        win32._set_data(win32.CF_UNICODETEXT, "x\0".encode("utf-16-le"))
        win32._set_data(win32.fmt("CanIncludeInClipboardHistory"), b"\0\0\0\0")
    assert clipboard.sensitive_format() == "CanIncludeInClipboardHistory"


def test_can_include_in_history_one_is_allowed(clipboard):
    with win32._Open():
        win32.user32.EmptyClipboard()
        win32._set_data(win32.CF_UNICODETEXT, "x\0".encode("utf-16-le"))
        win32._set_data(win32.fmt("CanIncludeInClipboardHistory"), b"\1\0\0\0")
    assert clipboard.sensitive_format() is None


def test_read_text_respects_limit(clipboard):
    win32.set_text("abcdefghij", private=False)
    assert clipboard.read_text(4) == "abcd"


def test_owner_is_this_process_after_our_write(clipboard):
    import os

    win32.set_text("mine", private=False)
    assert clipboard.owner_pid() in (None, os.getpid())  # NULL owner when opened without a window


def test_hotkey_parsing():
    assert win32.parse_hotkey("win+alt+v") == (win32.MOD_NOREPEAT | win32.MOD_WIN | win32.MOD_ALT, ord("V"))
    with pytest.raises(ValueError):
        win32.parse_hotkey("v")
