import argparse
import sys

from clipmind import __version__


def status() -> int:
    from clipmind import config, keys, win32

    cfg = config.load()
    data = config.data_dir()
    db = data / "history.db"
    model = data / "models" / cfg["model"] / "model.safetensors"
    print(f"data folder : {data}")
    print(f"history     : {'present' if db.exists() else 'none yet'} (encrypted; item count needs no unlock)")
    if db.exists():
        import sqlite3

        con = sqlite3.connect(db)
        (count,) = con.execute("SELECT COUNT(*) FROM items").fetchone()
        con.close()
        print(f"items       : {count}")
    print(f"key         : {'set up' if keys.public_key() else 'not set up'} (Credential Manager, Hello-wrapped)")
    print(f"model       : {'ok' if model.exists() else 'missing: python scripts/fetch_model.py'} ({cfg['model']})")
    print(f"hotkey      : {cfg['hotkey']}")
    for w in win32.windows_history_warnings():
        print(f"warning     : {w}: it keeps every copy, unfiltered")
    return 0


def wipe(yes: bool) -> int:
    from clipmind import config, keys, win32

    if not win32.single_instance():
        print("clipmind is running. Use 'Wipe all history' in its tray menu, or quit it first.")
        return 1
    if not yes and input("Delete ALL clipboard history and its keys? This can't be undone. [y/N] ").lower() != "y":
        print("Nothing deleted.")
        return 1
    db = config.data_dir() / "history.db"
    if db.exists():
        import sqlite3

        con = sqlite3.connect(db)
        con.execute("PRAGMA secure_delete=ON")
        with con:
            con.execute("DELETE FROM items")
        con.execute("VACUUM")
        con.close()
    keys.destroy()
    print("History and keys deleted.")
    return 0


def autostart(on: bool) -> int:
    from pathlib import Path

    from clipmind import win32

    pythonw = Path(sys.executable).with_name("pythonw.exe")
    win32.set_autostart(f'"{pythonw}" -m clipmind run' if on else None)
    print(f"autostart {'on' if on else 'off'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="clipmind", description="Private clipboard history for Windows.")
    parser.add_argument("--version", action="version", version=f"clipmind {__version__}")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("run", help="start clipmind (default)")
    sub.add_parser("status", help="show setup and warnings")
    w = sub.add_parser("wipe", help="delete all history and keys")
    w.add_argument("--yes", action="store_true", help="don't ask")
    a = sub.add_parser("autostart", help="start clipmind when you sign in")
    a.add_argument("state", choices=["on", "off"])
    args = parser.parse_args(argv)
    if args.cmd == "status":
        return status()
    if args.cmd == "wipe":
        return wipe(args.yes)
    if args.cmd == "autostart":
        return autostart(args.state == "on")
    from clipmind.app import run

    return run()


if __name__ == "__main__":
    sys.exit(main())
