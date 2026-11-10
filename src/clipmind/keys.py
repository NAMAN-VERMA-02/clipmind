"""Key custody.

An X25519 key pair protects the history. The private key is wrapped (AES-256-GCM)
with a key derived from a Windows Hello signature over a fixed challenge, and the
wrapped blob lives in Windows Credential Manager, never in a plain file. Hello keys
sign with RSA PKCS#1 v1.5, which is deterministic, so the same signature (and the
same wrap key) comes back on every unlock.

Writing needs only the public key: each item is a sealed box. Reading history
needs a Hello prompt.
"""

import ctypes
import os
from collections.abc import Callable
from ctypes import wintypes

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TARGET = "clipmind/v1"
HELLO_KEY_NAME = "clipmind"
CHALLENGE = b"clipmind-unlock-v1"
VERSION = b"\x01"

Signer = Callable[[bytes], bytes]


class KeyProblem(Exception):
    """Base for key problems; the message is safe to show and log."""


class HelloUnavailable(KeyProblem):
    pass


class UnlockFailed(KeyProblem):
    pass


def _hkdf(material: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(material)


# --- Windows Credential Manager ---------------------------------------------------------------------------


class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2  # this user on this machine; never roams with the profile
_ERROR_NOT_FOUND = 1168
_advapi = ctypes.WinDLL("advapi32", use_last_error=True)
_advapi.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIAL), wintypes.DWORD]
_advapi.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                              ctypes.POINTER(ctypes.POINTER(_CREDENTIAL))]
_advapi.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
_advapi.CredFree.argtypes = [ctypes.c_void_p]


def vault_write(target: str, blob: bytes) -> None:
    buf = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
    cred = _CREDENTIAL(Type=_CRED_TYPE_GENERIC, TargetName=target, CredentialBlobSize=len(blob),
                       CredentialBlob=buf, Persist=_CRED_PERSIST_LOCAL_MACHINE, UserName="clipmind")
    if not _advapi.CredWriteW(ctypes.byref(cred), 0):
        raise OSError(ctypes.get_last_error(), "CredWriteW failed")


def vault_read(target: str) -> bytes | None:
    ptr = ctypes.POINTER(_CREDENTIAL)()
    if not _advapi.CredReadW(target, _CRED_TYPE_GENERIC, 0, ctypes.byref(ptr)):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            return None
        raise OSError(err, "CredReadW failed")
    try:
        return ctypes.string_at(ptr.contents.CredentialBlob, ptr.contents.CredentialBlobSize)
    finally:
        _advapi.CredFree(ptr)


def vault_delete(target: str) -> None:
    if not _advapi.CredDeleteW(target, _CRED_TYPE_GENERIC, 0) and ctypes.get_last_error() != _ERROR_NOT_FOUND:
        raise OSError(ctypes.get_last_error(), "CredDeleteW failed")


# --- Windows Hello -----------------------------------------------------------------------------------------


def _winrt():
    from winrt.windows.security.credentials import (
        KeyCredentialCreationOption,
        KeyCredentialManager,
        KeyCredentialStatus,
    )
    from winrt.windows.security.cryptography import CryptographicBuffer

    return KeyCredentialManager, KeyCredentialCreationOption, KeyCredentialStatus, CryptographicBuffer


def hello_sign(challenge: bytes) -> bytes:
    """Sign `challenge` with clipmind's Hello key, creating it on first use. Shows the Hello prompt."""
    manager, option, status, cbuf = _winrt()
    if not manager.is_supported_async().get():
        raise HelloUnavailable("Windows Hello isn't set up. Add a PIN in Settings > Accounts > Sign-in options.")
    res = manager.open_async(HELLO_KEY_NAME).get()
    if res.status == status.NOT_FOUND:
        res = manager.request_create_async(HELLO_KEY_NAME, option.FAIL_IF_EXISTS).get()
    if res.status != status.SUCCESS:
        raise UnlockFailed(f"Windows Hello key unavailable ({status(res.status).name})")
    signed = res.credential.request_sign_async(cbuf.create_from_byte_array(challenge)).get()
    if signed.status != status.SUCCESS:
        raise UnlockFailed(f"Windows Hello didn't sign ({status(signed.status).name})")
    return bytes(signed.result)


NTE_NO_KEY = -2146893811  # 0x8009000D: "Key does not exist"


def hello_delete() -> None:
    manager, _, _, _ = _winrt()
    try:
        manager.delete_async(HELLO_KEY_NAME).get()
    except OSError as e:  # already gone (cancelled first setup, second wipe): deleting is idempotent (#13)
        if e.winerror != NTE_NO_KEY:
            raise


# --- key pair ------------------------------------------------------------------------------------------------


def setup(sign: Signer = hello_sign, target: str = TARGET) -> X25519PrivateKey:
    """Create the key pair, wrap the private half with the Hello-derived key, store it in Credential Manager.

    Returns the private key so the first session starts unlocked (the user just passed Hello).
    """
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    nonce = os.urandom(12)
    wrapped = AESGCM(_hkdf(sign(CHALLENGE), b"clipmind wrap v1")).encrypt(nonce, priv.private_bytes_raw(),
                                                                          VERSION + pub)
    vault_write(target, VERSION + pub + nonce + wrapped)
    return priv


def public_key(target: str = TARGET) -> X25519PublicKey | None:
    blob = vault_read(target)
    return X25519PublicKey.from_public_bytes(blob[1:33]) if blob and blob[:1] == VERSION else None


def unlock(sign: Signer = hello_sign, target: str = TARGET) -> X25519PrivateKey:
    blob = vault_read(target)
    if not blob or blob[:1] != VERSION:
        raise UnlockFailed("no clipmind key found; run clipmind once to set it up")
    pub, nonce, wrapped = blob[1:33], blob[33:45], blob[45:]
    try:
        raw = AESGCM(_hkdf(sign(CHALLENGE), b"clipmind wrap v1")).decrypt(nonce, wrapped, VERSION + pub)
    except InvalidTag:
        raise UnlockFailed("the Windows Hello key doesn't match this history (was Hello reset?)") from None
    priv = X25519PrivateKey.from_private_bytes(raw)
    if priv.public_key().public_bytes_raw() != pub:
        raise UnlockFailed("stored key pair is inconsistent")
    return priv


def destroy(target: str = TARGET, delete_hello: Callable[[], None] = hello_delete) -> None:
    """Crypto-shred: without these keys, any ciphertext left on disk can't be opened."""
    vault_delete(target)
    delete_hello()


# --- sealed boxes ----------------------------------------------------------------------------------------------


def _box_key(shared: bytes, eph_pub: bytes, pub: bytes) -> bytes:
    return _hkdf(shared, b"clipmind item v1" + eph_pub + pub)


def seal(pub: X25519PublicKey, plaintext: bytes, aad: bytes) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    nonce = os.urandom(12)
    key = _box_key(eph.exchange(pub), eph_pub, pub.public_bytes_raw())
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def open_box(priv: X25519PrivateKey, blob: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if the box was altered or isn't ours."""
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    return AESGCM(_box_key(shared, eph_pub, priv.public_key().public_bytes_raw())).decrypt(nonce, ct, aad)
