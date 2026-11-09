import hashlib
import hmac
import sqlite3
import uuid

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from clipmind import keys
from clipmind.store import BUCKET, Store, pad, unpad


def fake_hello(secret: bytes = b"test-hello"):
    return lambda challenge: hmac.new(secret, challenge, hashlib.sha256).digest()


@pytest.fixture
def target():
    name = f"clipmind-test/{uuid.uuid4()}"
    yield name
    keys.vault_delete(name)


@pytest.fixture
def pair():
    priv = X25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture
def store(tmp_path, pair):
    s = Store(str(tmp_path / "history.db"), pair[1])
    yield s
    s.close()


# --- keys ------------------------------------------------------------------------------------------------------


def test_credential_manager_roundtrip(target):
    assert keys.vault_read(target) is None
    keys.vault_write(target, b"\x00\x01blob")
    assert keys.vault_read(target) == b"\x00\x01blob"
    keys.vault_delete(target)
    assert keys.vault_read(target) is None


def test_setup_then_unlock_with_same_hello(target):
    pub = keys.setup(fake_hello(), target)
    assert keys.public_key(target).public_bytes_raw() == pub.public_bytes_raw()
    priv = keys.unlock(fake_hello(), target)
    assert priv.public_key().public_bytes_raw() == pub.public_bytes_raw()


def test_unlock_fails_with_a_different_hello_key(target):
    keys.setup(fake_hello(b"one"), target)
    with pytest.raises(keys.UnlockFailed):
        keys.unlock(fake_hello(b"two"), target)


def test_swapping_the_stored_public_key_breaks_unlock(target):
    keys.setup(fake_hello(), target)
    blob = keys.vault_read(target)
    other = X25519PrivateKey.generate().public_key().public_bytes_raw()
    keys.vault_write(target, blob[:1] + other + blob[33:])
    with pytest.raises(keys.UnlockFailed):
        keys.unlock(fake_hello(), target)


def test_vault_never_holds_the_raw_private_key(target):
    keys.setup(fake_hello(), target)
    raw = keys.unlock(fake_hello(), target).private_bytes_raw()
    assert raw not in keys.vault_read(target)


def test_destroy_removes_key_and_calls_hello_delete(target):
    keys.setup(fake_hello(), target)
    called = []
    keys.destroy(target, delete_hello=lambda: called.append(True))
    assert keys.vault_read(target) is None and called


def test_sealed_box_roundtrip_and_tamper(pair):
    priv, pub = pair
    box = keys.seal(pub, b"hello", b"aad")
    assert keys.open_box(priv, box, b"aad") == b"hello"
    with pytest.raises(InvalidTag):
        keys.open_box(priv, box, b"other aad")
    with pytest.raises(InvalidTag):
        keys.open_box(X25519PrivateKey.generate(), box, b"aad")
    assert keys.seal(pub, b"hello", b"aad") != box  # fresh ephemeral key each time


# --- store -----------------------------------------------------------------------------------------------------


def test_add_and_load_roundtrip(store, pair):
    store.add("docker compose up -d", b"\x01\x02" * 8, now=1_700_000_000)
    store.add("second clip ✓", b"", now=1_700_000_100)
    items = store.load(pair[0])
    assert [i.text for i in items] == ["docker compose up -d", "second clip ✓"]
    assert items[0].embedding == b"\x01\x02" * 8 and items[0].created_ms == 1_700_000_000_000


def test_nothing_plaintext_reaches_disk(tmp_path, store):
    marker = "UNIQUE-MARKER-clipmind-7f3a"
    store.add(marker, b"", now=1_700_000_000)
    store.close()
    raw = b"".join(p.read_bytes() for p in tmp_path.iterdir())
    assert marker.encode() not in raw and marker.encode("utf-16-le") not in raw


def test_padding_hides_exact_length(store):
    store.add("a" * 10, b"")
    store.add("b" * 100, b"")
    sizes = {len(r[0]) for r in store._db.execute("SELECT blob FROM items")}
    assert len(sizes) == 1
    assert unpad(pad(b"xyz")) == b"xyz" and len(pad(b"xyz")) % BUCKET == 0


def test_expire_removes_old_rows_only(store, pair):
    t0 = 1_700_000_000
    store.add("old", b"", now=t0)
    store.add("new", b"", now=t0 + 6 * 24 * 3600)
    removed = store.expire(now=t0 + 7 * 24 * 3600 + 2 * 3600)
    assert removed == 1 and [i.text for i in store.load(pair[0])] == ["new"]


def test_item_never_expires_early(store):
    t0 = 1_700_000_000
    store.add("x", b"", now=t0)
    assert store.expire(now=t0 + 7 * 24 * 3600 - 1) == 0


def test_cap_evicts_oldest(tmp_path, pair):
    s = Store(str(tmp_path / "cap.db"), pair[1], max_items=3)
    for i in range(5):
        s.add(f"clip {i}", b"")
    assert [i.text for i in s.load(pair[0])] == ["clip 2", "clip 3", "clip 4"]
    s.close()


def test_delete_overwrites_the_row(tmp_path, store):
    row = store.add("delete me", b"")
    blob = store._db.execute("SELECT blob FROM items WHERE id = ?", (row,)).fetchone()[0]
    store.delete(row)
    store.close()
    assert blob[:64] not in (tmp_path / "history.db").read_bytes()


def test_tampered_expiry_is_detected_and_row_dropped(store, pair):
    row = store.add("keep me short", b"")
    with store._db:
        store._db.execute("UPDATE items SET expires_hour = expires_hour + 1000 WHERE id = ?", (row,))
    assert store.load(pair[0]) == [] and store.count() == 0


def test_wipe_empties_and_vacuums(tmp_path, store):
    for i in range(50):
        store.add(f"clip {i}" * 20, b"")
    store.wipe()
    assert store.count() == 0
    store.close()
    db = sqlite3.connect(tmp_path / "history.db")
    assert db.execute("PRAGMA freelist_count").fetchone()[0] == 0
    db.close()
