"""Thin ctypes layer over the Win32 APIs clipmind needs. No logic lives here.

One hidden window (on its own thread) receives clipboard updates, the global
hotkey, session lock/sleep notifications and tray-icon events.
"""

import ctypes
import logging
import os
import time
import winreg
from collections.abc import Callable
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

WM_DESTROY, WM_CLOSE, WM_HOTKEY, WM_CLIPBOARDUPDATE = 0x0002, 0x0010, 0x0312, 0x031D
WM_WTSSESSION_CHANGE, WM_POWERBROADCAST, WM_APP, WM_COMMAND = 0x02B1, 0x0218, 0x8000, 0x0111
WM_LBUTTONUP, WM_RBUTTONUP = 0x0202, 0x0205
WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK = 0x2, 0x4, 0x7
PBT_APMSUSPEND = 0x4
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002
MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT = 0x1, 0x2, 0x4, 0x8, 0x4000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WM_TRAY = WM_APP + 1

EXCLUDE_FORMATS = ("ExcludeClipboardContentFromMonitorProcessing", "Clipboard Viewer Ignore")
ZERO_DWORD_FORMATS = ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")


def _sig(dll, name, restype, *argtypes):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = restype, list(argtypes)
    return fn


H, P = wintypes.HANDLE, ctypes.c_void_p
_sig(user32, "DefWindowProcW", LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
_sig(user32, "CreateWindowExW", wintypes.HWND, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
     ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, P)
_sig(user32, "GetClipboardOwner", wintypes.HWND)
_sig(user32, "GetForegroundWindow", wintypes.HWND)
_sig(user32, "GetClipboardData", H, wintypes.UINT)
_sig(user32, "SetClipboardData", H, wintypes.UINT, H)
_sig(user32, "OpenClipboard", wintypes.BOOL, wintypes.HWND)
_sig(user32, "IsClipboardFormatAvailable", wintypes.BOOL, wintypes.UINT)
_sig(user32, "RegisterClipboardFormatW", wintypes.UINT, wintypes.LPCWSTR)
_sig(user32, "GetWindowThreadProcessId", wintypes.DWORD, wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
_sig(user32, "GetWindowTextW", ctypes.c_int, wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
_sig(user32, "SetForegroundWindow", wintypes.BOOL, wintypes.HWND)
_sig(user32, "PostMessageW", wintypes.BOOL, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
_sig(user32, "LoadIconW", wintypes.HICON, wintypes.HINSTANCE, P)
_sig(user32, "CreatePopupMenu", wintypes.HMENU)
_sig(user32, "AppendMenuW", wintypes.BOOL, wintypes.HMENU, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR)
_sig(user32, "TrackPopupMenu", wintypes.BOOL, wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int,
     ctypes.c_int, wintypes.HWND, P)
_sig(user32, "DestroyMenu", wintypes.BOOL, wintypes.HMENU)
_sig(user32, "GetCursorPos", wintypes.BOOL, ctypes.POINTER(wintypes.POINT))
_sig(user32, "MessageBoxW", ctypes.c_int, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT)
_sig(user32, "RegisterWindowMessageW", wintypes.UINT, wintypes.LPCWSTR)
_sig(kernel32, "GlobalAlloc", H, wintypes.UINT, ctypes.c_size_t)
_sig(kernel32, "GlobalFree", H, H)
_sig(kernel32, "GlobalLock", P, H)
_sig(kernel32, "GlobalUnlock", wintypes.BOOL, H)
_sig(kernel32, "GlobalSize", ctypes.c_size_t, H)
_sig(kernel32, "OpenProcess", H, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
_sig(kernel32, "CloseHandle", wintypes.BOOL, H)
_sig(kernel32, "QueryFullProcessImageNameW", wintypes.BOOL, H, wintypes.DWORD, wintypes.LPWSTR,
     ctypes.POINTER(wintypes.DWORD))
_sig(kernel32, "GetModuleHandleW", wintypes.HMODULE, wintypes.LPCWSTR)

_sig(user32, "EmptyClipboard", wintypes.BOOL)
_sig(user32, "CloseClipboard", wintypes.BOOL)
_sig(user32, "AddClipboardFormatListener", wintypes.BOOL, wintypes.HWND)
_sig(user32, "RemoveClipboardFormatListener", wintypes.BOOL, wintypes.HWND)
_sig(user32, "RegisterHotKey", wintypes.BOOL, wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT)
_sig(user32, "UnregisterHotKey", wintypes.BOOL, wintypes.HWND, ctypes.c_int)
_sig(user32, "DestroyWindow", wintypes.BOOL, wintypes.HWND)
_sig(user32, "PostQuitMessage", None, ctypes.c_int)
_sig(user32, "GetMessageW", wintypes.BOOL, ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT)
_sig(user32, "TranslateMessage", wintypes.BOOL, ctypes.POINTER(wintypes.MSG))
_sig(user32, "DispatchMessageW", LRESULT, ctypes.POINTER(wintypes.MSG))
_sig(wtsapi32, "WTSRegisterSessionNotification", wintypes.BOOL, wintypes.HWND, wintypes.DWORD)
_sig(wtsapi32, "WTSUnRegisterSessionNotification", wintypes.BOOL, wintypes.HWND)

_formats: dict[str, int] = {}


def fmt(name: str) -> int:
    if name not in _formats:
        _formats[name] = user32.RegisterClipboardFormatW(name)
    return _formats[name]


# --- process info -------------------------------------------------------------------------------------------


def window_pid(hwnd) -> int | None:
    if not hwnd:
        return None
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value or None


def process_exe(pid: int | None) -> str | None:
    """Lowercase exe basename. LIMITED_INFORMATION works even for elevated processes."""
    if not pid:
        return None
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        buf, size = ctypes.create_unicode_buffer(1024), wintypes.DWORD(1024)
        if not kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return None
        return os.path.basename(buf.value).lower()
    finally:
        kernel32.CloseHandle(handle)


def window_title(hwnd) -> str:
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    return buf.value


# Chrome's window title never says "Incognito"; its accessible (MSAA) name does. Measured live on
# Chrome and Edge, 2026-11-09: title 'about:blank - Google Chrome', MSAA 'about:blank - Google Chrome (Incognito)'.
CHROMIUM_BROWSERS = {"chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "opera.exe", "opera_gx.exe"}


class _GUID(ctypes.Structure):
    _fields_ = [("a", ctypes.c_uint32), ("b", ctypes.c_uint16), ("c", ctypes.c_uint16), ("d", ctypes.c_ubyte * 8)]


class _VARIANT(ctypes.Structure):
    _fields_ = [("vt", ctypes.c_ushort), ("r1", ctypes.c_ushort), ("r2", ctypes.c_ushort), ("r3", ctypes.c_ushort),
                ("val", ctypes.c_longlong), ("pad", ctypes.c_longlong)]


_IID_IACCESSIBLE = _GUID(0x618736E0, 0x3C3D, 0x11CF,
                         (ctypes.c_ubyte * 8)(0x81, 0x0C, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71))
_GET_NAME = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, _VARIANT, ctypes.POINTER(ctypes.c_void_p))
_RELEASE = ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)


def accessible_name(hwnd) -> str:
    """MSAA name of a window (IAccessible::get_accName via its vtable), or '' if unavailable."""
    oleacc, ole32, oleaut32 = ctypes.WinDLL("oleacc"), ctypes.WinDLL("ole32"), ctypes.WinDLL("oleaut32")
    ole32.CoInitializeEx(None, 0x2)  # STA; S_FALSE / RPC_E_CHANGED_MODE are fine: COM is usable either way
    oleacc.AccessibleObjectFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD, ctypes.POINTER(_GUID),
                                                  ctypes.POINTER(ctypes.c_void_p)]
    oleaut32.SysFreeString.argtypes = [ctypes.c_void_p]
    acc = ctypes.c_void_p()
    if oleacc.AccessibleObjectFromWindow(hwnd, 0, ctypes.byref(_IID_IACCESSIBLE), ctypes.byref(acc)) != 0:
        return ""
    vtbl = ctypes.cast(ctypes.cast(acc, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.POINTER(ctypes.c_void_p))
    bstr = ctypes.c_void_p()
    try:
        ok = _GET_NAME(vtbl[10])(acc, _VARIANT(vt=3, val=0), ctypes.byref(bstr)) == 0  # VT_I4 CHILDID_SELF
        return ctypes.wstring_at(bstr) if ok and bstr.value else ""
    finally:
        if bstr.value:
            oleaut32.SysFreeString(bstr)
        _RELEASE(vtbl[2])(acc)


# --- clipboard ----------------------------------------------------------------------------------------------


class ClipboardBusy(OSError):
    pass


class _Open:
    """OpenClipboard with a few retries: another app may hold it for a moment."""

    def __init__(self, hwnd=None):
        self.hwnd = hwnd

    def __enter__(self):
        for _ in range(10):
            if user32.OpenClipboard(self.hwnd):
                return self
            time.sleep(0.01)
        raise ClipboardBusy(ctypes.get_last_error(), "OpenClipboard failed")

    def __exit__(self, *_):
        user32.CloseClipboard()


def _read_dword(format_id: int) -> int | None:
    handle = user32.GetClipboardData(format_id)
    ptr = kernel32.GlobalLock(handle) if handle else None
    if not ptr:
        return None
    try:
        return ctypes.c_uint32.from_address(ptr).value if kernel32.GlobalSize(handle) >= 4 else None
    finally:
        kernel32.GlobalUnlock(handle)


class Snapshot:
    """What clipmind may learn about the current clipboard, cheapest and least intrusive first.

    The text itself is read last (read_text), only after every metadata check passed,
    so a password manager's delayed-render data is never pulled.
    """

    def __init__(self, hwnd=None):
        self.hwnd = hwnd

    def sensitive_format(self) -> str | None:
        for name in EXCLUDE_FORMATS:
            if user32.IsClipboardFormatAvailable(fmt(name)):
                return name
        present = [n for n in ZERO_DWORD_FORMATS if user32.IsClipboardFormatAvailable(fmt(n))]
        if present:
            try:
                with _Open(self.hwnd):
                    for name in present:
                        if _read_dword(fmt(name)) != 1:
                            return name
            except ClipboardBusy:
                return present[0]  # fail closed: can't confirm it's allowed
        return None

    def owner_pid(self) -> int | None:
        return window_pid(user32.GetClipboardOwner())

    def owner_exe(self) -> str | None:
        return process_exe(self.owner_pid())

    def foreground(self) -> tuple[str | None, str]:
        """(exe, title). For Chromium browsers the accessible name is appended, since only it says Incognito."""
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None, ""
        exe, title = process_exe(window_pid(hwnd)), window_title(hwnd)
        if exe in CHROMIUM_BROWSERS:
            title += " | " + accessible_name(hwnd)
        return exe, title

    def has_text(self) -> bool:
        return bool(user32.IsClipboardFormatAvailable(CF_UNICODETEXT))

    def read_text(self, limit: int) -> str | None:
        """At most `limit` characters; the caller drops anything that long as too big."""
        with _Open(self.hwnd):
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            ptr = kernel32.GlobalLock(handle) if handle else None
            if not ptr:
                return None
            try:
                chars = min(kernel32.GlobalSize(handle) // 2, limit)
                return ctypes.wstring_at(ptr, chars).split("\0", 1)[0]
            finally:
                kernel32.GlobalUnlock(handle)


def _set_data(format_id: int, data: bytes) -> None:
    handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(data))
    ptr = kernel32.GlobalLock(handle)
    ctypes.memmove(ptr, data, len(data))
    kernel32.GlobalUnlock(handle)
    if not user32.SetClipboardData(format_id, handle):
        kernel32.GlobalFree(handle)  # on success the clipboard owns the memory
        raise OSError(ctypes.get_last_error(), "SetClipboardData failed")


def set_text(text: str, hwnd=None, private: bool = True) -> None:
    """Put text on the clipboard. `private` marks it so Win+V history, cloud clipboard and monitors skip it."""
    with _Open(hwnd):
        user32.EmptyClipboard()
        _set_data(CF_UNICODETEXT, (text + "\0").encode("utf-16-le"))
        if private:
            _set_data(fmt("ExcludeClipboardContentFromMonitorProcessing"), b"\0\0\0\0")
            for name in ZERO_DWORD_FORMATS:
                _set_data(fmt(name), b"\0\0\0\0")


# --- keyboard -----------------------------------------------------------------------------------------------


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class _INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("ki", _KEYBDINPUT), ("mi", _MOUSEINPUT)]

    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _U)]


_sig(user32, "SendInput", wintypes.UINT, wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int)
VK_CONTROL, VK_V, KEYEVENTF_KEYUP = 0x11, 0x56, 0x2


def paste_into(hwnd) -> bool:
    """Focus `hwnd` and send Ctrl+V. Fails silently into elevated windows (UIPI); the text stays on the clipboard."""
    if hwnd:
        user32.SetForegroundWindow(hwnd)
        time.sleep(0.05)
    keys = [(VK_CONTROL, 0), (VK_V, 0), (VK_V, KEYEVENTF_KEYUP), (VK_CONTROL, KEYEVENTF_KEYUP)]
    arr = (_INPUT * 4)(*(_INPUT(type=1, ki=_KEYBDINPUT(wVk=vk, dwFlags=flags)) for vk, flags in keys))
    return user32.SendInput(4, arr, ctypes.sizeof(_INPUT)) == 4


def foreground_window():
    return user32.GetForegroundWindow()


VK_NAMES = {"space": 0x20, "enter": 0x0D, "insert": 0x2D, **{f"f{i}": 0x6F + i for i in range(1, 13)}}


def parse_hotkey(spec: str) -> tuple[int, int]:
    mods, vk = MOD_NOREPEAT, None
    for part in spec.lower().replace(" ", "").split("+"):
        if part in ("win", "alt", "ctrl", "control", "shift"):
            mods |= {"win": MOD_WIN, "alt": MOD_ALT, "ctrl": MOD_CONTROL, "control": MOD_CONTROL,
                     "shift": MOD_SHIFT}[part]
        elif len(part) == 1 and part.isalnum():
            vk = ord(part.upper())
        elif part in VK_NAMES:
            vk = VK_NAMES[part]
        else:
            raise ValueError(f"unknown hotkey part: {part!r}")
    if vk is None or mods == MOD_NOREPEAT:
        raise ValueError("hotkey needs at least one modifier and one key, e.g. win+alt+v")
    return mods, vk


# --- process-wide settings ----------------------------------------------------------------------------------


def harden_process() -> None:
    """Keep heap memory (which may hold clip text) out of Windows Error Reporting crash dumps."""
    kernel32.WerSetFlags.argtypes = [wintypes.DWORD]
    kernel32.WerSetFlags(0x1)  # WER_FAULT_REPORTING_FLAG_NOHEAP


def enable_dpi_awareness() -> None:
    user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # PER_MONITOR_AWARE_V2


def windows_history_warnings() -> list[str]:
    """Windows' own clipboard history and cloud sync keep everything, unfiltered."""
    warnings = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard") as key:
            for value, msg in (("EnableClipboardHistory", "Windows clipboard history (Win+V) is on"),
                               ("EnableCloudClipboard", "Windows cloud clipboard sync is on")):
                try:
                    if winreg.QueryValueEx(key, value)[0]:
                        warnings.append(msg)
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    return warnings


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def set_autostart(command: str | None) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if command:
            winreg.SetValueEx(key, "clipmind", 0, winreg.REG_SZ, command)
        else:
            try:
                winreg.DeleteValue(key, "clipmind")
            except FileNotFoundError:
                pass


# --- the hidden window ----------------------------------------------------------------------------------------


class _WNDCLASSW(ctypes.Structure):
    _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HBRUSH), ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR)]


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256), ("uVersion", wintypes.UINT), ("szInfoTitle", wintypes.WCHAR * 64),
                ("dwInfoFlags", wintypes.DWORD), ("guidItem", ctypes.c_byte * 16), ("hBalloonIcon", wintypes.HICON)]


_sig(user32, "RegisterClassW", wintypes.ATOM, ctypes.POINTER(_WNDCLASSW))
_sig(shell32, "Shell_NotifyIconW", wintypes.BOOL, wintypes.DWORD, ctypes.POINTER(_NOTIFYICONDATAW))
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP = 0x1, 0x2, 0x4
IDI_SHIELD, IDI_WARNING = 32518, 32515
MB_YESNO, MB_ICONWARNING, MB_DEFBUTTON2, MB_TOPMOST, IDYES = 0x4, 0x30, 0x100, 0x40000, 6
TPM_RETURNCMD, TPM_RIGHTBUTTON = 0x100, 0x2

MENU = [(1, "Open"), (2, "Pause capture"), (3, "Lock now"), (4, "Wipe all history…"), (5, "Quit")]


class Window:
    """Owns the hidden window and its message loop. Call run() on a dedicated thread.

    Callbacks run on that thread: on_clipboard(Snapshot), on_hotkey(), on_lock(), on_menu(command_id).
    """

    def __init__(self, hotkey: tuple[int, int], on_clipboard: Callable, on_hotkey: Callable,
                 on_lock: Callable, on_menu: Callable):
        self.hotkey, self.on_clipboard, self.on_hotkey = hotkey, on_clipboard, on_hotkey
        self.on_lock, self.on_menu = on_lock, on_menu
        self.hwnd = None
        self.paused = False
        self.hotkey_ok = False
        self._proc = WNDPROC(self._wndproc)  # keep a reference: ctypes callbacks must outlive the window
        self._taskbar_created = user32.RegisterWindowMessageW("TaskbarCreated")

    def run(self) -> None:
        hinst = kernel32.GetModuleHandleW(None)
        wc = _WNDCLASSW(lpfnWndProc=self._proc, hInstance=hinst, lpszClassName="clipmind.hidden")
        user32.RegisterClassW(ctypes.byref(wc))
        self.hwnd = user32.CreateWindowExW(0, "clipmind.hidden", "clipmind", 0, 0, 0, 0, 0, None, None, hinst, None)
        user32.AddClipboardFormatListener(self.hwnd)
        self.hotkey_ok = bool(user32.RegisterHotKey(self.hwnd, 1, *self.hotkey))
        wtsapi32.WTSRegisterSessionNotification(self.hwnd, 0)  # NOTIFY_FOR_THIS_SESSION
        self._tray(NIM_ADD)
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def stop(self) -> None:
        if self.hwnd:
            user32.PostMessageW(self.hwnd, WM_CLOSE, 0, 0)

    def set_paused(self, paused: bool) -> None:
        self.paused = paused
        self._tray(NIM_MODIFY)

    def confirm(self, text: str) -> bool:
        return user32.MessageBoxW(self.hwnd, text, "clipmind",
                                  MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_TOPMOST) == IDYES

    def _tray(self, action: int) -> None:
        tip = "clipmind: capture paused" if self.paused else "clipmind: capturing (secrets filtered)"
        icon = user32.LoadIconW(None, ctypes.c_void_p(IDI_WARNING if self.paused else IDI_SHIELD))
        nid = _NOTIFYICONDATAW(cbSize=ctypes.sizeof(_NOTIFYICONDATAW), hWnd=self.hwnd, uID=1,
                               uFlags=NIF_MESSAGE | NIF_ICON | NIF_TIP, uCallbackMessage=WM_TRAY, hIcon=icon,
                               szTip=tip)
        shell32.Shell_NotifyIconW(action, ctypes.byref(nid))

    def _menu(self) -> None:
        menu = user32.CreatePopupMenu()
        for cmd, label in MENU:
            user32.AppendMenuW(menu, 0, cmd, "Resume capture" if cmd == 2 and self.paused else label)
        pt = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pt))
        user32.SetForegroundWindow(self.hwnd)  # otherwise the menu won't close when clicking elsewhere
        cmd = user32.TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, self.hwnd, None)
        user32.DestroyMenu(menu)
        if cmd:
            self.on_menu(cmd)

    def _wndproc(self, hwnd, msg, wparam, lparam):
        try:
            if msg == WM_CLIPBOARDUPDATE:
                self.on_clipboard(Snapshot(hwnd))
            elif msg == WM_HOTKEY:
                self.on_hotkey()
            elif msg == WM_WTSSESSION_CHANGE and wparam in (WTS_SESSION_LOCK, WTS_REMOTE_DISCONNECT,
                                                             WTS_CONSOLE_DISCONNECT):
                self.on_lock()
            elif msg == WM_POWERBROADCAST and wparam == PBT_APMSUSPEND:
                self.on_lock()
            elif msg == WM_TRAY and lparam == WM_LBUTTONUP:
                self.on_menu(1)
            elif msg == WM_TRAY and lparam == WM_RBUTTONUP:
                self._menu()
            elif msg == self._taskbar_created:
                self._tray(NIM_ADD)  # Explorer restarted
            elif msg == WM_CLOSE:
                self._tray(NIM_DELETE)
                user32.RemoveClipboardFormatListener(hwnd)
                user32.UnregisterHotKey(hwnd, 1)
                wtsapi32.WTSUnRegisterSessionNotification(hwnd)
                user32.DestroyWindow(hwnd)
                return 0
            elif msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
        except Exception as e:  # never let an exception cross the ctypes boundary
            logging.getLogger(__name__).error("window callback failed: %s", type(e).__name__)
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)
