"""Records docs/demo.gif: the real popup and search over a made-up history (no real clipboard, no Hello, no disk).

    python scripts/demo.py --dry   # print what each demo query finds
    python scripts/demo.py         # play the demo and record it with ffmpeg (gdigrab)
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
import tkinter as tk
from pathlib import Path

from clipmind import config, win32
from clipmind.embed import Embedder
from clipmind.popup import Popup
from clipmind.search import Index

HISTORY = [  # all invented
    "IndiGo 6E 2134 · Delhi (DEL) → Goa (GOI) · Sat 14 Dec, dep 06:10 · seat 12F",
    "SELECT email, COUNT(*) FROM users GROUP BY email HAVING COUNT(*) > 1;",
    "Dr. Mehra Dental Clinic, 2nd floor, Sector 18 Market, Noida 201301",
    "git rebase -i HEAD~3",
    "https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup",
    "Team sync moved to Thursday 4:30 pm, same Meet link",
    "docker compose up -d --build api",
    "Grocery: oats, paneer, spinach, 2L milk, coffee beans",
    "Thanks for the quick turnaround! Attaching the revised invoice for October.",
    "kubectl logs -f deploy/web --since=10m",
    "Return window for the headphones closes on 22 Nov",
    "def chunks(xs, n):\n    return [xs[i:i + n] for i in range(0, len(xs), n)]",
    "Landlord: rent goes up 5% from January, deposit stays the same",
    "ffmpeg -i in.mp4 -vf scale=1280:-2 -c:a copy out.mp4",
    "Reminder: renew the car insurance before 3 Dec",
    "The quarterly review deck is in the shared drive under Q3/final",
    "pip install --require-hashes -r requirements-dev.txt",
    "Mom's birthday dinner — book a table for 6 at 8 pm",
    "Regex for Indian pincodes: ^[1-9][0-9]{5}$",
    "Electricity bill: ₹2,340 due 18 Nov",
]
QUERIES = ["plane ticket", "sql to find repeated emails", "tooth doctor"]  # "when is my flight" misses: see README


def build_index() -> Index:
    emb = Embedder(config.data_dir() / "models" / "potion-base-8M")
    index, now = Index(emb), int(time.time() * 1000)
    for i, text in enumerate(reversed(HISTORY)):
        index.add(i, text, now - (len(HISTORY) - i) * 47 * 60_000, emb.embed(text))
    return index


class DemoApp:
    def __init__(self, index: Index):
        self.index = index

    def search(self, query):
        return self.index.search(query)

    def status_text(self):
        return f"{len(self.index)} items · capturing · Enter paste · Shift+Del delete · Esc close"

    def touch(self): ...
    def paste(self, hit): ...
    def delete(self, hit): ...
    def toggle_pause(self): ...


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--out", default="docs/demo.gif")
    args = ap.parse_args()
    index = build_index()
    if args.dry:
        for q in QUERIES:
            print(q, "->", [h.text[:50] for h in index.search(q)[:3]])
        return 0
    win32.enable_dpi_awareness()
    root = tk.Tk()
    root.withdraw()
    popup = Popup(root, DemoApp(index))
    popup.win.title("clipmind-demo")  # gdigrab finds the window by title
    root.update()  # lay out first, as the running app has by the time the hotkey fires
    popup.show()
    root.update()
    ffmpeg = shutil.which("ffmpeg")
    tmp = Path(tempfile.mkdtemp())
    rec = subprocess.Popen([ffmpeg, "-y", "-loglevel", "error", "-f", "gdigrab", "-framerate", "15", "-draw_mouse", "0",  # noqa: S603
                            "-i", "title=clipmind-demo", str(tmp / "demo.mp4")], stdin=subprocess.PIPE)

    steps, t = [], 1200
    for q in QUERIES:
        for i in range(1, len(q) + 1):
            steps.append((t, lambda s=q[:i]: (popup.query.delete(0, "end"), popup.query.insert(0, s), popup.refresh())))
            t += 70
        t += 2200
    steps.append((t, lambda: popup._move(1)))
    steps.append((t + 500, lambda: popup._move(1)))
    for at, fn in steps:
        root.after(at, fn)
    root.after(t + 1800, root.quit)
    root.mainloop()
    rec.communicate(b"q")
    out = Path(args.out)
    out.parent.mkdir(exist_ok=True)
    palette = tmp / "palette.png"
    subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-i", str(tmp / "demo.mp4"),  # noqa: S603
                    "-vf", "fps=12,palettegen=stats_mode=diff", str(palette)], check=True)
    subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-i", str(tmp / "demo.mp4"), "-i", str(palette),  # noqa: S603
                    "-lavfi", "fps=12[x];[x][1:v]paletteuse=dither=none", str(out)], check=True)
    print(out, out.stat().st_size // 1024, "KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
