"""Secret detectors. Pure functions, no I/O.

`check(text)` returns the name of the first detector that fires, or None if the
clip looks safe. A clip with any secret in it is dropped whole: partial
redaction is easy to get wrong.
"""

import base64
import binascii
import json
import math
import re
import unicodedata
from collections import Counter

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e"), None)


def normalise(text: str) -> str:
    """NFKC folds fullwidth/compat characters; zero-width chars are removed so they can't split a secret."""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def _b64decode(s: str, urlsafe: bool = False) -> bytes | None:
    try:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s) if urlsafe else base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        return None


# --- private keys -----------------------------------------------------------------------------------------

PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-\d+:")


def private_key(text: str) -> bool:
    return bool(PRIVATE_KEY.search(text))


# --- JWT --------------------------------------------------------------------------------------------------

JWT = re.compile(r"\b(eyJ[A-Za-z0-9_-]{5,})\.(eyJ[A-Za-z0-9_-]{5,})\.[A-Za-z0-9_-]*")


def _json_segment(segment: str):
    raw = _b64decode(segment, urlsafe=True)
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def jwt(text: str) -> bool:
    for m in JWT.finditer(text):
        header = _json_segment(m.group(1))
        if isinstance(header, dict) and "alg" in header and _json_segment(m.group(2)) is not None:
            return True
    return False


# --- API keys and credentials -----------------------------------------------------------------------------

API_KEY = re.compile(
    r"""
      \b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b                 # AWS access key id
    | \bgh[pousr]_[A-Za-z0-9]{36,}\b                          # GitHub tokens
    | \bgithub_pat_[A-Za-z0-9_]{60,}\b
    | \bglpat-[A-Za-z0-9_-]{20,}\b                            # GitLab
    | \bxox[abposr]-[A-Za-z0-9-]{10,}\b | \bxapp-\d-[A-Za-z0-9-]{20,}  # Slack
    | \b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b            # Stripe secret/restricted
    | \bwhsec_[A-Za-z0-9+/=]{24,}                             # Stripe webhook secret
    | \bAIza[0-9A-Za-z_-]{35}\b                               # Google API key
    | \bya29\.[A-Za-z0-9_-]{30,} | \b1//0[A-Za-z0-9_-]{30,}   # Google OAuth access/refresh
    | \bsk-ant-[A-Za-z0-9_-]{20,}                             # Anthropic
    | \bsk-(?:proj-|svcacct-|admin-)?(?=[\w-]*\d)(?=[\w-]*[A-Z])[A-Za-z0-9_-]{20,}  # OpenAI-style
    | \bhf_[A-Za-z0-9]{30,}\b                                 # Hugging Face
    | \bnpm_[A-Za-z0-9]{36}\b | \bpypi-[A-Za-z0-9_-]{50,}     # npm, PyPI
    | \bdckr_pat_[A-Za-z0-9_-]{20,}                           # Docker Hub
    | \bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}            # SendGrid
    | \bSK[0-9a-f]{32}\b                                      # Twilio API key
    | \bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b                  # Shopify
    | \bdop_v1_[a-f0-9]{64}\b                                 # DigitalOcean
    | \b(?:ntn_|secret_)[A-Za-z0-9]{40,}\b                    # Notion
    | \bgsk_[A-Za-z0-9]{40,}\b | \bxai-[A-Za-z0-9]{40,}\b     # Groq, xAI
    | \bAGE-SECRET-KEY-1[0-9A-Z]{50,}                         # age
    | \b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b       # Discord bot
    | \bAccountKey=[A-Za-z0-9+/=]{40,}                        # Azure storage connection string
    | \bSharedAccessKey=[A-Za-z0-9+/=]{30,}
    | \b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@               # credentials in a URL (user:pass@)
    | \bBearer\s+(?=[\w.~+/-]*\d)[A-Za-z0-9._~+/-]{20,}=*     # Authorization: Bearer <token>
    """,
    re.VERBOSE,
)
BASIC_AUTH = re.compile(r"\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")

# The secret word must END the name (optionally + _key/_value), so `tokenizer` or `max_tokens` don't count.
SECRET_NAME = (
    r"[\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"  # noqa: S105
    r"|client[_-]?secret|credentials?)(?:[_-]?(?:key|value|str|string))?"
)
ASSIGNMENT = re.compile(
    rf"""(?i)(?:^|(?<=[\s"'{{,;(]))(?:{SECRET_NAME})["']?\s*[:=]\s*(?P<q>["']?)(?P<val>[^\s"'`,;)}}\]]{{6,}})(?P=q)"""
)
NOT_A_VALUE = {"bearer", "basic", "string", "required", "optional", "hidden", "password", "secret", "token",
               "undefined", "null", "none", "true", "false", "changeme", "example", "placeholder"}
# Values that point at a secret instead of being one: $VAR, %VAR%, <placeholder>, {{ template }},
# calls, indexing, dotted names (config.password), UPPER_SNAKE names, masks.
REFERENCE = re.compile(r"[$%<{(\[]|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$|^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^\*+$|^[xX]+$")


def api_key(text: str) -> bool:
    if API_KEY.search(text):
        return True
    for m in BASIC_AUTH.finditer(text):
        raw = _b64decode(m.group(1))
        if raw and b":" in raw and raw.isascii():
            return True
    return any(
        m.group("val").lower() not in NOT_A_VALUE and not REFERENCE.search(m.group("val"))
        for m in ASSIGNMENT.finditer(text)
    )


# --- card numbers ---------------------------------------------------------------------------------------------

CARD = re.compile(r"(?<!\d)(?:\d[ \-._]?){12,18}\d(?!\d)")
_ANY = set(range(13, 20))
# (low prefix, high prefix, allowed lengths); prefixes compared on the same number of digits.
BRANDS = [
    ("4", "4", {13, 16, 19}),                                       # Visa
    ("51", "55", {16}), ("2221", "2720", {16}),                     # Mastercard
    ("34", "34", {15}), ("37", "37", {15}),                         # Amex
    ("6011", "6011", {16, 19}), ("644", "649", {16, 19}),           # Discover
    ("60", "60", {16}), ("65", "65", {16, 19}), ("508", "508", {16}), ("81", "82", {16}),  # RuPay
    ("3528", "3589", {16, 17, 18, 19}),                             # JCB
    ("300", "305", _ANY - {13}), ("36", "36", _ANY - {13}), ("38", "39", {16, 17, 18, 19}),  # Diners
    ("62", "62", {16, 17, 18, 19}),                                 # UnionPay
    ("50", "50", _ANY), ("56", "69", _ANY),                         # Maestro
]


def luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def card(text: str) -> bool:
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if luhn(digits) and any(lo <= digits[: len(lo)] <= hi and len(digits) in ok for lo, hi, ok in BRANDS):
            return True
    return False


# --- Aadhaar --------------------------------------------------------------------------------------------------

AADHAAR = re.compile(r"(?<!\d)(?<!\d\.)[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?!\d|\.\d)")
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def aadhaar(text: str) -> bool:
    # VIDs (16 digits) are skipped on purpose: they are made to be shared and revocable,
    # and a Verhoeff check would flag 1 in 10 of all 16-digit numbers.
    return any(verhoeff(re.sub(r"\D", "", m.group())) for m in AADHAAR.finditer(text))


# --- PAN ------------------------------------------------------------------------------------------------------

PAN = re.compile(r"\b[A-Z]{3}[ABCFGHLJPTE][A-Z]\d{4}[A-Z]\b")


def pan(text: str) -> bool:
    return bool(PAN.search(text))


# --- OTP ------------------------------------------------------------------------------------------------------

# A bare 4-5 digit clip is kept: ports, years and room numbers are far more common than 4-digit OTPs.
BARE_OTP = re.compile(r"\d{6,8}|\d{3}[ -]\d{3}|\d{4}[ -]\d{4}")
OTP_WORDS = re.compile(
    r"\b(?:otp|one[- ]time (?:password|passcode|pin|code)|verification code|security code|login code|"
    r"auth(?:entication)? code|passcode|2fa|code is|is your (?:[\w-]+ ){0,3}code)\b",
    re.IGNORECASE,
)
# Digit groups glued to other digits (phone numbers, amounts, dates) are not OTPs.
OTP_NUMBER = re.compile(r"(?<![\d₹$])(?<!\d[ .,/-])(?:\d{4,8}|\d{3}[ -]\d{3})(?!\d|[ .,/-]\d|%)")


def otp(text: str) -> bool:
    if BARE_OTP.fullmatch(text.strip()):
        return True
    return bool(OTP_WORDS.search(text) and OTP_NUMBER.search(text))


# --- high-entropy tokens --------------------------------------------------------------------------------------

URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)
QUERY_PARAM = re.compile(r"[?&#]([^=&#\s]+)=([^&#\s]+)")
SECRET_PARAM = re.compile(
    r"^(?:\w*token|key|api[_-]?key|apikey|secret|client_secret|sig|signature|password|passwd|pass|pwd|auth|"
    r"code|session|sid|credential|x-amz-signature|x-amz-credential|x-amz-security-token)$",
    re.IGNORECASE,
)
# Public material that is random by nature: data URIs, hash digests, SSH public keys, non-private PEM/PGP blocks.
PUBLIC_MATERIAL = re.compile(
    r"data:[\w/+.-]*(?:;[\w=.-]+)*;base64,[A-Za-z0-9+/=]+"
    r"|\b(?:sha(?:1|224|256|384|512)|md5)[-:][A-Za-z0-9+/=]+"
    r"|\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+AAAA[A-Za-z0-9+/=]+"
    r"|-----BEGIN ((?:(?!PRIVATE)[A-Z0-9 ])+)-----.*?-----END \1-----",
    re.IGNORECASE | re.DOTALL,
)
TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX = re.compile(r"(?:0x)?[0-9a-fA-F]+")
WORDISH = re.compile(r"[a-z]{8}|[A-Z]{8}")


def shannon(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _readable_base64(tok: str) -> bool:
    """Base64 that decodes to readable text is encoded data (a JSON header, a word), not a random key."""
    raw = _b64decode(tok, urlsafe="-" in tok or "_" in tok)
    return bool(raw) and sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) >= 0.95 * len(raw)


def _random_looking(tok: str) -> bool:
    tok = tok.strip("=-_/+")
    if len(tok) < 20 or HEX.fullmatch(tok) or WORDISH.search(tok):
        return False
    if not (re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok) and re.search(r"\d", tok)):
        return False
    return shannon(tok) >= min(4.0, math.log2(len(tok)) - 0.6) and not _readable_base64(tok)


def high_entropy(text: str) -> bool:
    for url in URL.findall(text):
        for name, value in QUERY_PARAM.findall(url):
            if SECRET_PARAM.match(name) and len(value) >= 16 and shannon(value) >= 3.5:
                return True
    text = UUID.sub(" ", URL.sub(" ", PUBLIC_MATERIAL.sub(" ", text)))  # URL paths are not secrets
    return any(_random_looking(t) for t in TOKEN.findall(text))


# --- passwords (a backstop: human-chosen passwords look like ordinary words) ------------------------------------

STRONG_SYMBOL = re.compile(r"[!@#$%^&*+=?~|<>{}\[\]();:'\",`\\]")
NOT_PASSWORD = re.compile(
    r"""
      ^[#@]\w                                 # hashtag / mention
    | ^[\w.+-]+@[\w-]+(?:\.[\w-]+)+$          # email
    | ^[a-z][a-z0-9+.-]*://                   # URL
    | [/\\]                                   # paths
    | \.[a-z][a-z0-9]{1,4}$                   # ends in a file extension / TLD
    | ^v?\d+(?:[.\-:/]\d+)*$                  # numbers, versions, dates
    """,
    re.VERBOSE,
)
RUN = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+|[^A-Za-z\d]")


def password(text: str) -> bool:
    tok = text.strip()
    if not 8 <= len(tok) <= 64 or any(c.isspace() for c in tok) or NOT_PASSWORD.search(tok) or _readable_base64(tok):
        return False
    lower, upper, digit, symbol = (bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z\d]"))
    if lower + upper + digit + symbol < 3 or not (digit or symbol):
        return False
    strong = STRONG_SYMBOL.findall(tok)
    if strong and (lower or upper) and (digit or len(strong) > 1):
        return True
    runs = RUN.findall(tok)  # random strings break into many tiny runs; identifiers into a few words
    return lower and upper and digit and len(runs) >= 4 and len(tok) / len(runs) <= 2.0


# --- entry point -----------------------------------------------------------------------------------------------

DETECTORS = [private_key, jwt, api_key, card, aadhaar, pan, otp, high_entropy, password]


def check(text: str) -> str | None:
    """Name of the first detector that flags `text`, or None if it looks safe to store."""
    norm = normalise(text)
    for detector in DETECTORS:
        if detector(norm):
            return detector.__name__
    return None
