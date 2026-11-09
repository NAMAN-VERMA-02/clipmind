"""Independent eval sources, fetched at run time from pinned commits and checked by SHA-256.

Nothing here is vendored into the repo; files are cached in eval/out/sources/ (gitignored).
This is eval tooling, not part of the clipmind package, so it may use the network.
"""

import ast
import hashlib
import json
import urllib.request
from pathlib import Path

OUT = Path(__file__).parent / "out" / "sources"
DS = "https://raw.githubusercontent.com/Yelp/detect-secrets/5e141933554a0b74e7341841f318be21e895339c"

# detect-secrets (Apache-2.0) plugin tests: their `(payload, should_flag)` pairs, labelled by its authors.
DETECT_SECRETS = {
    "aws_key": "cf274b9d3ab9d86047737ba82eb00503330df3d519a6860be0efe4ad57f37599",
    "basic_auth": "70d4c5bf1220a424dbe4feb48f6afca15abf8543a79f830111cb58452a11dd22",
    "discord": "d4b6eaf800a2ca5b30b72384bd3e681119c52160da41cfd6e0a619c2f13b0fda",
    "github_token": "bf12f16a00ac2ec611f6d93aa1f40aa1e6e1aecccc59d5ef82ca89502849b44f",
    "gitlab_token": "c5d9898f6a1718c9a4cfdb62d2757c44b5e5036829fb7cde739bf1e184d1e0a3",
    "jwt": "c01742dc4f0cda325d3399503c016e962fcdc6b59a8a66ebf09cd6ca049eb8d7",
    "keyword": "fb53f17ef8de7efe272e9b7dac0e5a282ea5bed46263346ed34d902b93869de4",
    "npm": "05e5559925c88992807b2548e28b79d869f386e0f51eb07a22e657151d7d8a74",
    "openai": "3cff721f61e75a91d3b6b55676001c5589418d8341ccded036cc937beed745fb",
    "private_key": "71cd4c13a1f38133cb4f50dbaa976e97533c9dd0fb2c4af832e2d54a8498ea01",
    "pypi_token": "ad2274ca4cb0234887f9c97fc0accd06a6f798572055725759952a571213186b",
    "sendgrid": "efed43ac61765e16358038cc43b5603ed0a2ead37bbe5f0165047a9596b4105b",
    "slack": "a0d179cf0c161d52c4ebd9d58c07079eb421e0d4513af07d3f4483865bd69488",
    "stripe_key": "bae5a4250aab62c3d5b6bf8ddf079bc4640b068688b369a28ffeb71eeacb49f7",
    "twilio": "16e27cca848ef34417499b7a0978b93cf70cbe98884efc2759be04faa6193b0b",
    "azure_storage_key": "1d746b9c8d637eaf2fbe1e24dab7cf66cd45d5fe39b2b71a09706834614af9b4",
    "artifactory": "7f3fe276b235f26e0373948eb072f9fa5f2913f0aba126f7e72ca144de746723",
    "cloudant": "bbd0156d4f17e8e5ffee399462683854087acf439cbae148fc8bb182f7c5a651",
    "ibm_cloud_iam": "965228b677db7e417067d0ccdd2010fd96b91a690b0b7c8836410f4f8b82d29a",
    "ibm_cos_hmac": "b4d09e1590f06b34b660f24a355a6b435158c89fefec4d19919325e739b5c1fd",
    "mailchimp_key": "ca127e07e566e9f5fa4b5aed94edab6fef2d3d68075c7276a508ea5b965ecae9",
    "softlayer": "70e21cdd10ddc2d9cc4a9f6bcf13fc8f5483dd5fbc8337871b36c1d942dd56bf",
    "square_oauth": "997f9eb708012a84faaa090889d1822faa3a91af5c46450b1bc1ecd757663e40",
    "telegram_token": "13af272aa92d0af5ea101b94fba287e0fc5ebeaf644b97484b0a52861e5e0f1a",
}
FILES = {
    "seclists_10k.txt": ("https://raw.githubusercontent.com/danielmiessler/SecLists/"
                         "913b327317496d062bcc7cace524aaad8a693be2/Passwords/Common-Credentials/10k-most-common.txt",
                         "68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce"),
    "eff_large_wordlist.txt": ("https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt",
                               "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"),
    **{f"ds_{name}_test.py": (f"{DS}/tests/plugins/{name}_test.py", sha) for name, sha in DETECT_SECRETS.items()},
}


def fetch(name: str) -> str:
    url, expected = FILES[name]
    path = OUT / name
    if not path.exists():
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 - pinned https URLs only
            data = resp.read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise RuntimeError(f"{name}: SHA-256 {actual} != pinned {expected}")
        OUT.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return path.read_text(encoding="utf-8")


def detect_secrets_samples() -> list[tuple[str, str, bool]]:
    """(plugin, payload, should_flag) from every parametrize list of (str, bool) pairs in the plugin tests."""
    out = []
    for name in DETECT_SECRETS:
        tree = ast.parse(fetch(f"ds_{name}_test.py"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Tuple) and len(node.elts) == 2:
                payload, flag = node.elts
                if (isinstance(payload, ast.Constant) and isinstance(payload.value, str)
                        and isinstance(flag, ast.Constant) and isinstance(flag.value, bool)):
                    out.append((name, payload.value, flag.value))
    return out


def seclists_passwords(n: int) -> list[str]:
    return [p for p in fetch("seclists_10k.txt").splitlines() if p][:n]


def eff_words() -> list[str]:
    return [line.split("\t")[1] for line in fetch("eff_large_wordlist.txt").splitlines() if "\t" in line]


def test_cards() -> list[dict]:
    return json.loads((Path(__file__).parent / "data" / "test_cards.json").read_text(encoding="utf-8"))["cards"]
