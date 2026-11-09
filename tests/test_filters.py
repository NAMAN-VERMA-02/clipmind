"""One test per secret type, plus near-misses that must be kept.

This is the DEV set: thresholds may be tuned against it. The held-out set in
eval/near_misses_heldout.jsonl is never used here.

Fake tokens are assembled at run time so no secret-shaped literal sits in the
source (GitHub push protection would rightly object).
"""

import base64
import hashlib
import hmac
import json
import random
import string

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from clipmind import filters
from clipmind.filters import check

R = random.Random(1109)
ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(R.choice(alphabet) for _ in range(n))


def b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def make_jwt(alg: str = "HS256") -> str:
    head, body = b64url({"alg": alg, "typ": "JWT"}), b64url({"sub": "1029", "name": "Test User", "iat": 1731150840})
    sig = hmac.new(b"k", f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def luhn_complete(prefix: str, length: int) -> str:
    body = prefix + rand(length - len(prefix) - 1, string.digits)
    return next(body + c for c in string.digits if filters.luhn(body + c))


def verhoeff_complete(first11: str) -> str:
    return next(first11 + c for c in string.digits if filters.verhoeff(first11 + c))


def pem(key, fmt=serialization.PrivateFormat.PKCS8, enc=None) -> str:
    return key.private_bytes(serialization.Encoding.PEM, fmt, enc or serialization.NoEncryption()).decode()


RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC = ec.generate_private_key(ec.SECP256R1())
ED = ed25519.Ed25519PrivateKey.generate()
AADHAAR = verhoeff_complete("4829" + "1037" + "562")
VISA = luhn_complete("4", 16)

SECRETS = {
    "private_key": [
        pem(RSA),
        pem(EC, serialization.PrivateFormat.TraditionalOpenSSL),
        pem(ED, serialization.PrivateFormat.OpenSSH),
        pem(RSA, enc=serialization.BestAvailableEncryption(b"pw")),
        "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + rand(64) + "\n-----END PGP PRIVATE KEY BLOCK-----",
    ],
    "jwt": [make_jwt(), "token=" + make_jwt("RS256"), f'{{"id_token": "{make_jwt()}"}}'],
    "api_key": [
        "AKIA" + rand(16, UPPER_DIGITS),
        "gh" + "p_" + rand(36),
        "sk" + "_live_" + rand(24),
        "AI" + "za" + rand(35, ALNUM + "_-"),
        "xo" + "xb-" + rand(12, string.digits) + "-" + rand(24),
        "sk" + "-ant-api03-" + rand(40, ALNUM + "-_"),
        "sk" + "-proj-" + rand(48),
        "hf" + "_" + rand(34),
        "gl" + "pat-" + rand(20),
        "S" + "K" + rand(32, "0123456789abcdef"),
        "postgres://admin:" + rand(12) + "@db.internal:5432/app",
        'password = "hunter2!x"',
        "DB_PASSWORD=" + rand(14),
        '{"client_secret": "' + rand(30) + '"}',
        "api_key: " + rand(24),
        "Authorization: Basic " + base64.b64encode(b"admin:hunter2").decode(),
        "Authorization: Bearer " + rand(40),
    ],
    "card": [
        VISA, "4111 1111 1111 1111", "5555-5555-5555-4444", "3782 822463 10005", "6011111111111117",
        luhn_complete("6522", 16), luhn_complete("508", 16), "4111.1111.1111.1111",
        f"pay with {VISA} please",
        "\uff14\uff11\uff11\uff11 \uff11\uff11\uff11\uff11 \uff11\uff11\uff11\uff11 \uff11\uff11\uff11\uff11",  # fullwidth
        "4111\u200b1111\u200b1111\u200b1111",  # zero-width spaces
    ],
    "aadhaar": [AADHAAR, f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}", f"{AADHAAR[:4]}-{AADHAAR[4:8]}-{AADHAAR[8:]}",
                f"My Aadhaar is {AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}."],
    "pan": ["ABCPE1234F", "PAN: AAACB7731K", "my pan is BNZPM2501F."],
    "otp": ["482913", "482 913", "  48291374 ", "Your OTP is 482913.", "123456 is your verification code for Swiggy",
            "Use 4829 as your one-time password", "\uff14\uff18\uff12\uff19\uff11\uff13", "OTP is 482 913."],
    "high_entropy": [
        rand(32),
        rand(40, ALNUM + "/+"),
        "https://api.example.com/v1/download?token=" + rand(32),
        "https://bucket.s3.amazonaws.com/f.pdf?X-Amz-Signature=" + R.randbytes(32).hex(),
        "\n".join(rand(64, ALNUM + "+/") for _ in range(4)),
    ],
    "password": ["Xk9#mQ2$vL", "P@ssw0rd!", "Tr0ub4dor&3", "hT4kq9Zr", "  zQ7!pLm2#w  "],
}

SAFE = {
    "private_key": [
        RSA.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        EC.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "Where do I put my private key on Windows?",
    ],
    "jwt": ["eyJhbGciOiJIUzI1NiJ9", "eyJfoo.eyJbar.baz", "1.2.3", "api.v2.users"],
    "api_key": [
        "skeleton-key-design-pattern", "AKIA1234", "password = os.getenv('PW')", "token: ${{ github.token }}",
        "auth_token = settings.AUTH_TOKEN", "tokenizer = AutoTokenizer.from_pretrained('bert-base')",
        '"max_tokens": 4096', "Bearer of good news", "Basic Instructions Before Leaving Earth",
        "Basic internationalization support", "http://localhost:3000/@user/profile", "git@github.com:org/repo.git",
        "mailto:someone@example.com", 'secret = ""', "password: ********", "export API_KEY=$MY_KEY",
    ],
    "card": ["Order 4111 1111 1111 1112", "1234-5678-9012-3456", "978-93-5019-482-7", "Ph: 9876543210, Alt: 9123456780",
             "490154203237518", "Batch 2022-2026, roll 2200290100145"],
    "aadhaar": ["1234 5678 9012", verhoeff_complete("4829" + "1037" + "562")[:-1] + "x", "Call 9876 5432 10",
                "XXXX XXXX 4321"],
    "pan": ["ABCDE1234F", "abcpe1234f", "GSTIN 07ABCPE1234F1Z5", "MH02AB1234"],
    "otp": ["2024", "8080", "Room 1204", "Call me at 9:30", "₹125000 only", "Invoice 20240311", "PIN: 4521",
            "otp verification failed", "The OTP feature shipped in v2.3.1", "We sent an OTP to +91 98765 43210"],
    "high_entropy": [
        hashlib.sha1(b"x").hexdigest(), "c9bf9e57-1685-4c89-bafb-ff5af830be8a",
        "https://drive.google.com/file/d/1Qw" + rand(30) + "/view",
        "sha512-" + base64.b64encode(R.randbytes(64)).decode(),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + rand(43, ALNUM + "+/") + " me@laptop",
        "Supercalifragilisticexpialidocious2024", "data:image/png;base64," + base64.b64encode(R.randbytes(90)).decode(),
        "AbstractSingletonProxyFactoryBean2",
    ],
    "password": ["Hello-World", "snake_case_var", "MyComponent2", "kiet-2026", "v1.2.3-beta", "user@example.com",
                 "#ThrowbackThursday", r"C:\temp\x.txt", "README.md", "Python3.11", "x86_64-linux-gnu",
                 "B.Tech-CSE-2027", "iPhone16Pro", "COVID-19", "Win32_Service"],
}


@pytest.mark.parametrize(("kind", "text"), [(k, t) for k, ts in SECRETS.items() for t in ts])
def test_secret_is_dropped(kind, text):
    assert check(text) is not None, f"{kind} not caught: {text[:60]!r}"
    assert getattr(filters, kind)(filters.normalise(text)), f"{kind} detector itself missed it"


@pytest.mark.parametrize(("kind", "text"), [(k, t) for k, ts in SAFE.items() for t in ts])
def test_near_miss_is_kept(kind, text):
    assert check(text) is None, f"{kind} near-miss dropped by {check(text)}: {text[:60]!r}"


def test_every_detector_has_positive_and_near_miss_cases():
    names = {d.__name__ for d in filters.DETECTORS}
    assert names == set(SECRETS) == set(SAFE)


def test_known_checksums():
    assert filters.luhn("79927398713") and not filters.luhn("79927398710")
    assert filters.verhoeff("2363") and not filters.verhoeff("2364")


def test_normalise_folds_fullwidth_and_strips_zero_width():
    assert filters.normalise("\uff21\uff22\u200b\uff11") == "AB1"
