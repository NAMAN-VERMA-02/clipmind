"""Settings: defaults, overridden by %APPDATA%\\clipmind\\config.json.

List settings in the file are ADDED to the defaults, never replace them, so a
config edit can't silently remove a password manager from the blocklist.
"""

import json
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULTS: dict = {
    "hotkey": "win+alt+v",
    "ttl_days": 7,
    "idle_lock_minutes": 10,
    "quarantine_seconds": 120,
    "max_items": 10_000,
    "max_chars": 32_000,
    "model": "potion-base-8M",
    # Lowercase exe names. Password managers, Phone Link (OTP "Copy code"), desktop authenticators.
    "blocked_apps": [
        "keepass.exe", "keepassxc.exe", "keepassxc-proxy.exe", "1password.exe", "bitwarden.exe", "dashlane.exe",
        "enpass.exe", "nordpass.exe", "keeperpasswordmanager.exe", "roboform.exe", "robotaskbaricon.exe",
        "proton pass.exe", "protonpass.exe", "lastpass.exe", "pwsafe.exe", "psono.exe", "buttercup.exe",
        "phoneexperiencehost.exe", "authy desktop.exe", "winauth.exe", "ente auth.exe", "ente_auth.exe",
        "2fast.exe", "credentialuibroker.exe",
    ],
    # Window-title markers of private browsing windows (checked on the foreground window).
    "private_title_markers": ["InPrivate", "Incognito", "Private Browsing", "Private window", "Tor Browser"],
    # Window-title keywords of banking sites/apps.
    "blocked_title_keywords": ["NetBanking", "Net Banking", "Internet Banking", "Online Banking", "OnlineSBI",
                               "YONO", "Retail Banking", "Corporate Banking"],
}


def data_dir() -> Path:
    """%LOCALAPPDATA% (never Roaming) so the history doesn't follow a roaming profile."""
    base = os.environ.get("CLIPMIND_DATA_DIR") or os.path.join(os.environ["LOCALAPPDATA"], "clipmind")
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_path() -> Path:
    return Path(os.environ.get("CLIPMIND_CONFIG") or os.path.join(os.environ["APPDATA"], "clipmind", "config.json"))


def load(path: Path | None = None) -> dict:
    cfg = {k: list(v) if isinstance(v, list) else v for k, v in DEFAULTS.items()}
    path = path or config_path()
    if not path.exists():
        return cfg
    try:
        user = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        log.warning("config ignored: %s", type(e).__name__)
        return cfg
    for key, value in user.items() if isinstance(user, dict) else ():
        default = DEFAULTS.get(key)
        if default is None or type(value) is not type(default):
            log.warning("config key ignored: %s", key)
        elif isinstance(default, list):
            cfg[key] += [str(v) for v in value]
        elif isinstance(default, int) and value <= 0:
            log.warning("config key ignored (must be positive): %s", key)
        else:
            cfg[key] = value
    cfg["blocked_apps"] = [a.lower() for a in cfg["blocked_apps"]]
    return cfg
