"""The real Windows Hello path. Needs a person to approve 2-3 prompts, so it's skipped by default:

    pytest -m hello -s
"""

import uuid

import pytest

from clipmind import keys

pytestmark = pytest.mark.hello


def test_real_hello_wraps_and_unwraps_the_key(monkeypatch):
    # A throwaway Hello key and vault entry, so the real "clipmind" ones are never touched.
    monkeypatch.setattr(keys, "HELLO_KEY_NAME", f"clipmind-test-{uuid.uuid4().hex[:8]}")
    target = f"clipmind-test/{uuid.uuid4()}"
    try:
        print("\nApprove the Windows Hello prompts (create key, then sign twice).")
        priv = keys.setup(keys.hello_sign, target)
        again = keys.unlock(keys.hello_sign, target)  # only works if Hello's signature is deterministic
        assert again.private_bytes_raw() == priv.private_bytes_raw()
        assert keys.public_key(target).public_bytes_raw() == priv.public_key().public_bytes_raw()
    finally:
        keys.destroy(target, delete_hello=keys.hello_delete)
    assert keys.vault_read(target) is None
