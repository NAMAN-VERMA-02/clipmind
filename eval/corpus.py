"""Builds the labelled eval corpora. Secrets come from independent sources where one exists."""

import base64
import hashlib
import hmac
import json
import random
import secrets as pysecrets
import shutil
import string
import subprocess
import sysconfig
import tempfile
from pathlib import Path

import sources
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

EVAL = Path(__file__).parent
SKIP_DIRS = {"test", "tests", "idle_test", "site-packages", "__pycache__"}


def jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (EVAL / name).read_text(encoding="utf-8").splitlines() if line.strip()]


# --- real-world safe text -----------------------------------------------------------------------------------


def stdlib_code(n: int, seed: int) -> list[str]:
    """Random 1-5 line snippets from CPython's own Lib/*.py (test suites excluded)."""
    lib = Path(sysconfig.get_paths()["stdlib"])
    files = sorted(p for p in lib.rglob("*.py") if not SKIP_DIRS & set(p.relative_to(lib).parts))
    rnd, out = random.Random(seed), []
    while len(out) < n:
        lines = rnd.choice(files).read_text(encoding="utf-8", errors="ignore").splitlines()
        if not lines:
            continue
        start = rnd.randrange(len(lines))
        snippet = "\n".join(lines[start : start + rnd.randint(1, 5)]).strip()
        if len(snippet) >= 10:
            out.append(snippet)
    return out


def stdlib_prose(n: int, seed: int) -> list[str]:
    """Paragraphs of the Python reference docs shipped in pydoc_data."""
    from pydoc_data.topics import topics

    paras = sorted({p.strip() for text in topics.values() for p in text.split("\n\n") if len(p.strip()) >= 40})
    return random.Random(seed).sample(paras, n)


# --- secrets ---------------------------------------------------------------------------------------------------


def private_keys() -> list[tuple[str, str]]:
    """Real keys minted by `cryptography` and the system ssh-keygen, in the formats people copy."""
    enc, out = serialization.Encoding.PEM, []
    keys = {"rsa2048": rsa.generate_private_key(65537, 2048), "rsa3072": rsa.generate_private_key(65537, 3072),
            "ec-p256": ec.generate_private_key(ec.SECP256R1()), "ec-p384": ec.generate_private_key(ec.SECP384R1()),
            "ed25519": ed25519.Ed25519PrivateKey.generate(), "dsa2048": dsa.generate_private_key(2048)}
    formats = {"traditional": serialization.PrivateFormat.TraditionalOpenSSL,
               "pkcs8": serialization.PrivateFormat.PKCS8, "openssh": serialization.PrivateFormat.OpenSSH}
    for kname, key in keys.items():
        for fname, fmt in formats.items():
            try:
                pem = key.private_bytes(enc, fmt, serialization.NoEncryption()).decode()
            except ValueError:  # e.g. Ed25519 has no "traditional" form
                continue
            out.append((f"{kname}/{fname}", pem))
        out.append((f"{kname}/pkcs8-encrypted", key.private_bytes(
            enc, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw")).decode()))
    pkcs8 = keys["rsa2048"].private_bytes(enc, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    out.append(("gcp-service-account-json", json.dumps({"type": "service_account", "private_key": pkcs8})))
    out.append(("body-without-armour", "\n".join(pkcs8.strip().splitlines()[1:-1])))
    keygen = shutil.which("ssh-keygen")
    if keygen:
        with tempfile.TemporaryDirectory() as tmp:
            for kind in ("rsa", "ecdsa", "ed25519"):
                path = Path(tmp) / kind
                subprocess.run([keygen, "-q", "-t", kind, "-N", "", "-f", str(path)], check=True)  # noqa: S603
                out.append((f"ssh-keygen/{kind}", path.read_text()))
    return out


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwts(rnd: random.Random) -> list[tuple[str, str]]:
    """JWTs actually signed with HMAC, RSA, ECDSA and EdDSA keys."""
    rsa_key, ec_key = rsa.generate_private_key(65537, 2048), ec.generate_private_key(ec.SECP256R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()

    def sign(alg: str, msg: bytes) -> bytes:
        if alg.startswith("HS"):
            return hmac.new(pysecrets.token_bytes(32), msg, getattr(hashlib, "sha" + alg[2:])).digest()
        if alg == "RS256":
            return rsa_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
        if alg == "ES256":
            r, s = decode_dss_signature(ec_key.sign(msg, ec.ECDSA(hashes.SHA256())))
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return ed_key.sign(msg)

    out = []
    for alg in ("HS256", "HS384", "HS512", "RS256", "ES256", "EdDSA"):
        for i in range(10):
            claims = {"sub": str(rnd.randint(1, 10**6)), "iat": 1_731_000_000 + i, "exp": 1_731_003_600 + i,
                      "email": f"user{i}@example.com", "role": rnd.choice(["admin", "user", "viewer"])}
            head = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
            body = _b64url(json.dumps(claims).encode())
            token = f"{head}.{body}." + _b64url(sign(alg, f"{head}.{body}".encode()))
            context = ["{}", "Authorization: Bearer {}", '{{"access_token": "{}", "token_type": "Bearer"}}',
                       "token={}; Path=/; HttpOnly"][i % 4]
            out.append((alg, context.format(token)))
    return out


def cards() -> list[tuple[str, str]]:
    out = []
    for c in sources.test_cards():
        digits = c["number"].replace(" ", "")
        groups = " ".join(digits[i : i + 4] for i in range(0, len(digits), 4))
        out += [("as-published", c["number"]), ("digits-only", digits), ("grouped-4", groups),
                ("in-sentence", f"Card {c['number']} exp 03/30 cvv 737")]
    return out


def otp_messages(rnd: random.Random) -> list[tuple[str, str]]:
    lines = (EVAL / "data" / "otp_messages.txt").read_text(encoding="utf-8").splitlines()
    msgs = [("message", line.replace("\\n", "\n")) for line in lines if line and not line.startswith("#")]
    return msgs + [("bare-6-digit", f"{rnd.randrange(10**6):06d}") for _ in range(200)]


def verhoeff_aadhaar(rnd: random.Random) -> str:
    from clipmind.filters import verhoeff

    while True:
        body = str(rnd.randint(2, 9)) + "".join(rnd.choice(string.digits) for _ in range(10))
        for c in string.digits:
            if verhoeff(body + c):
                return body + c


def aadhaar(rnd: random.Random) -> list[tuple[str, str]]:
    out = []
    for i in range(300):
        a = verhoeff_aadhaar(rnd)
        spaced = f"{a[:4]} {a[4:8]} {a[8:]}"
        out.append((["contiguous", "spaced", "dashed", "in-sentence"][i % 4],
                    [a, spaced, spaced.replace(" ", "-"), f"Aadhaar No.: {spaced}."][i % 4]))
    return out


def pans(rnd: random.Random) -> list[tuple[str, str]]:
    up = string.ascii_uppercase
    out = []
    for i in range(300):
        p = ("".join(rnd.choice(up) for _ in range(3)) + rnd.choice("PCHFATBLJGE") + rnd.choice(up)
             + "".join(rnd.choice(string.digits) for _ in range(4)) + rnd.choice(up))
        out.append((["bare", "in-sentence"][i % 2], [p, f"PAN: {p}"][i % 2]))
    return out


def passwords(rnd: random.Random) -> list[tuple[str, str]]:
    alpha = string.ascii_letters + string.digits
    words = sources.eff_words()
    out = [("seclists-top-1000", p) for p in sources.seclists_passwords(1000)]
    for i in range(1000):  # what password-manager generators produce
        pool = alpha + ("!@#$%^&*" if i % 2 else "")
        out.append(("generated-random", "".join(rnd.choice(pool) for _ in range(rnd.choice([12, 14, 16, 20])))))
    for i in range(500):
        sep = ["-", " ", "_", "."][i % 4]
        out.append(("diceware-passphrase", sep.join(rnd.choice(words) for _ in range(rnd.randint(3, 6)))))
    return out


def random_tokens(rnd: random.Random) -> list[tuple[str, str]]:
    out = []
    for _ in range(100):
        out.append(("alnum-32", "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(32))))
        out.append(("base64-40", base64.b64encode(rnd.randbytes(30)).decode()))
        out.append(("urlsafe-43", base64.urlsafe_b64encode(rnd.randbytes(32)).rstrip(b"=").decode()))
        out.append(("hex-64", rnd.randbytes(32).hex()))
    return out
