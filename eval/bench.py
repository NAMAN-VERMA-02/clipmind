"""Performance on this machine, through clipmind's real code paths, at 10,000 items.

    python eval/bench.py    # writes eval/results/bench.json and prints a table

The Windows Hello prompt is replaced by a fixed signer (a person can't be benchmarked);
everything after it (unwrap, decrypt, index) is the real code.
"""

import hashlib
import hmac
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
import winreg
from pathlib import Path

import numpy as np
import psutil
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from filters_eval import meta
from search_eval import MODELS, build_corpus, model_dir

from clipmind import config, filters, keys
from clipmind.capture import Capture
from clipmind.embed import Embedder
from clipmind.search import Index
from clipmind.store import Store

RESULTS = Path(__file__).parent / "results" / "bench.json"
SIGN = lambda c: hmac.new(b"bench", c, hashlib.sha256).digest()  # noqa: E731 - stands in for the Hello prompt


def pct(xs: list[float], p: float) -> float:
    return round(float(np.percentile(xs, p)) * 1000, 3)  # seconds -> ms


def machine() -> dict:
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
        cpu = winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
    return {"cpu": cpu, "cores_logical": psutil.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
            "os": platform.platform(), "cpu_busy_before_run_pct": psutil.cpu_percent(interval=2)}


def unlock(store: Store, emb: Embedder, priv) -> Index:
    """What App._unlocked does: decrypt every row, rebuild the index from stored embeddings."""
    index = Index(emb)
    for item in sorted(store.load(priv), key=lambda i: i.created_ms):
        index.add(item.id, item.text, item.created_ms, np.frombuffer(item.embedding, dtype=np.float16))
    index.matrix  # noqa: B018 - stack now, as the first search would
    return index


def run_model(name: str, texts: list[str], queries: list[str], tmp: Path) -> dict:
    target = f"clipmind-bench/{uuid.uuid4()}"
    try:
        priv = keys.setup(SIGN, target)
        store = Store(str(tmp / f"{name}.db"), priv.public_key(), max_items=10_000)
        emb = Embedder(model_dir(name))
        persist, dropped = [], 0
        for text in texts:  # the work done per clip once its quarantine ends
            t = time.perf_counter()
            if filters.check(text):
                dropped += 1
                continue
            vec = emb.embed(text)
            store.add(text, vec.astype(np.float16).tobytes())
            persist.append(time.perf_counter() - t)
        t = time.perf_counter()
        keys.unlock(SIGN, target)
        index = unlock(store, emb, priv)
        unlock_s = time.perf_counter() - t
        index.search("warm up")
        lat = []
        for i in range(1000):
            t = time.perf_counter()
            index.search(queries[i % len(queries)])
            lat.append(time.perf_counter() - t)
        store.close()
        db_bytes = (tmp / f"{name}.db").stat().st_size
        return {"items_stored": len(index), "dropped_by_filters": dropped,
                "persist_ms": {"p50": pct(persist, 50), "p95": pct(persist, 95), "p99": pct(persist, 99)},
                "unlock_10k_s": round(unlock_s, 3),
                "search_ms": {"p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99),
                              "mean": round(statistics.mean(lat) * 1000, 3)},
                "db_mb": round(db_bytes / 2**20, 2), "db_bytes_per_item": round(db_bytes / len(index))}
    finally:
        keys.vault_delete(target)


MEMORY_PROBE = r"""
import json, sys, time, tkinter
t = time.perf_counter()
import numpy as np, psutil
import clipmind.app  # everything the running app imports (tk, win32, capture, keys, store, search)
from clipmind import keys
from clipmind.embed import Embedder
from clipmind.search import Index
from clipmind.store import Store
root = tkinter.Tk(); root.withdraw()
emb = Embedder(__import__("pathlib").Path(sys.argv[1]))
priv = keys.X25519PrivateKey.from_private_bytes(bytes.fromhex(sys.argv[3]))
store = Store(sys.argv[2], priv.public_key())
store.expire()
cold = time.perf_counter() - t
p = psutil.Process()
locked = p.memory_full_info()
index = Index(emb)
for item in sorted(store.load(priv), key=lambda i: i.created_ms):
    index.add(item.id, item.text, item.created_ms, np.frombuffer(item.embedding, dtype=np.float16))
index.search("flight booking")
unlocked = p.memory_full_info()
print(json.dumps({"cold_start_s": round(cold, 3), "locked": [locked.rss, locked.uss],
                  "unlocked": [unlocked.rss, unlocked.uss]}))
"""


def memory(name: str, db: Path, priv_hex: str) -> dict:
    out = subprocess.run([sys.executable, "-c", MEMORY_PROBE, str(model_dir(name)), str(db), priv_hex],  # noqa: S603
                         capture_output=True, text=True, check=True)
    r = json.loads(out.stdout)
    mb = lambda b: round(b / 2**20, 1)  # noqa: E731
    return {"cold_start_s": r["cold_start_s"],
            "locked_mb": {"rss": mb(r["locked"][0]), "uss": mb(r["locked"][1])},
            "unlocked_10k_mb": {"rss": mb(r["unlocked"][0]), "uss": mb(r["unlocked"][1])}}


def quarantine() -> dict:
    """Clear-clipboard delays of real password managers vs the 120 s quarantine (real Capture code, fake clock)."""
    delays = {"KeePassXC default": 10, "KeePass default": 12, "Bitwarden 10 s": 10, "Bitwarden 20 s": 20,
              "Bitwarden 30 s": 30, "Bitwarden 1 min": 60, "1Password 90 s": 90, "Bitwarden 2 min": 120,
              "Bitwarden 5 min": 300}

    class Snap:
        def __init__(self, text):
            self.text = text

        def owner_pid(self):
            return 1

        def owner_exe(self):
            return "chrome.exe"  # a browser extension: no exclusion flags, not blocklisted

        def foreground(self):
            return "chrome.exe", "Vault"

        def sensitive_format(self):
            return None

        def has_text(self):
            return bool(self.text)

        def read_text(self, limit):
            return self.text

    out = {}
    for label, delay in delays.items():
        stored, clock = [], [0.0]
        cap = Capture(config.load(Path(os.devnull)), stored.append, lambda c=clock: c[0])
        cap.handle(Snap("correct horse battery staple"))
        for _ in range(0, delay, 5):  # the app flushes every 5 s
            clock[0] += 5
            if clock[0] < delay:
                cap.flush()
        clock[0] = delay
        cap.handle(Snap(None))  # the password manager clears the clipboard
        clock[0] += 600
        cap.flush()
        out[label] = "discarded" if not stored else "persisted"
    return out


def main() -> int:
    items, queries = build_corpus()
    texts, qs = [t for _, t in items], [q["query"] for q in queries]
    res = {"meta": {**meta(), "command": "python eval/bench.py", **machine()}, "models": {}}
    with tempfile.TemporaryDirectory() as tmp:
        for name in MODELS:
            r = run_model(name, texts, qs, Path(tmp))
            priv = X25519PrivateKey.generate()  # fresh store for the memory probe; no vault entry needed
            target_db = Path(tmp) / f"{name}-mem.db"
            store = Store(str(target_db), priv.public_key())
            emb = Embedder(model_dir(name))
            for text in texts:
                if not filters.check(text):
                    store.add(text, emb.embed(text).astype(np.float16).tobytes())
            store.close()
            r["memory"] = memory(name, target_db, priv.private_bytes_raw().hex())
            res["models"][name] = r
            print(name, json.dumps(r, indent=1))
    res["quarantine"] = quarantine()
    print(json.dumps(res["quarantine"], indent=1))
    RESULTS.parent.mkdir(exist_ok=True)
    RESULTS.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
