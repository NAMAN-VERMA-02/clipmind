"""Encrypted history on disk.

Each row is a sealed box (see keys.py). The only plaintext column is the hour the
row expires, so expiry runs while locked; the exact copy time lives inside the
ciphertext. Payloads are padded to 256-byte buckets so a row's size doesn't
reveal the exact text length. Deleted pages are zeroed by SQLite (secure_delete).
"""

import sqlite3
import struct
import threading
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from clipmind import keys

BUCKET = 256
_HEAD = struct.Struct("<qI")  # created_at_ms, embedding byte length


@dataclass
class Item:
    id: int
    created_ms: int
    text: str
    embedding: bytes


def _aad(expires_hour: int) -> bytes:
    return b"clipmind/v1|" + str(expires_hour).encode()


def pad(payload: bytes) -> bytes:
    framed = struct.pack("<I", len(payload)) + payload
    return framed + bytes(-len(framed) % BUCKET)


def unpad(padded: bytes) -> bytes:
    (n,) = struct.unpack_from("<I", padded)
    return padded[4 : 4 + n]


class Store:
    def __init__(self, path: str, public: X25519PublicKey, ttl_hours: int = 7 * 24, max_items: int = 10_000):
        self.public, self.ttl_hours, self.max_items = public, ttl_hours, max_items
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        for pragma in ("secure_delete=ON", "journal_mode=DELETE", "temp_store=MEMORY"):
            self._db.execute(f"PRAGMA {pragma}")
        self._db.execute("CREATE TABLE IF NOT EXISTS items "
                         "(id INTEGER PRIMARY KEY, expires_hour INTEGER NOT NULL, blob BLOB NOT NULL)")

    def add(self, text: str, embedding: bytes, now: float | None = None) -> int:
        now = time.time() if now is None else now
        expires_hour = int(now // 3600) + self.ttl_hours + 1  # rounded up: never expires early
        payload = _HEAD.pack(int(now * 1000), len(embedding)) + embedding + text.encode("utf-8")
        blob = keys.seal(self.public, pad(payload), _aad(expires_hour))
        with self._lock, self._db:
            row_id = self._db.execute("INSERT INTO items (expires_hour, blob) VALUES (?, ?)",
                                      (expires_hour, blob)).lastrowid
            self._db.execute("DELETE FROM items WHERE id NOT IN (SELECT id FROM items ORDER BY id DESC LIMIT ?)",
                             (self.max_items,))
        return row_id

    def load(self, priv: X25519PrivateKey) -> list[Item]:
        """Decrypt every row. A row that fails authentication was altered (or isn't ours) and is deleted."""
        with self._lock:
            rows = self._db.execute("SELECT id, expires_hour, blob FROM items ORDER BY id").fetchall()
        items, bad = [], []
        for row_id, expires_hour, blob in rows:
            try:
                payload = unpad(keys.open_box(priv, blob, _aad(expires_hour)))
            except (InvalidTag, struct.error, ValueError):
                bad.append(row_id)
                continue
            created_ms, emb_len = _HEAD.unpack_from(payload)
            body = payload[_HEAD.size :]
            items.append(Item(row_id, created_ms, body[emb_len:].decode("utf-8"), body[:emb_len]))
        for row_id in bad:
            self.delete(row_id)
        return items

    def delete(self, row_id: int) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM items WHERE id = ?", (row_id,))

    def expire(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        with self._lock, self._db:
            return self._db.execute("DELETE FROM items WHERE expires_hour <= ?", (int(now // 3600),)).rowcount

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM items").fetchone()[0]

    def wipe(self) -> None:
        with self._lock:
            with self._db:
                self._db.execute("DELETE FROM items")
            self._db.execute("VACUUM")

    def close(self) -> None:
        with self._lock:
            self._db.close()
