"""Download a pinned embedding model and verify it. Run once after installing.

This script is the ONLY networked code in the repository, and it lives outside
the clipmind package on purpose: the app itself never touches the network.

    python scripts/fetch_model.py                 # potion-base-8M (default)
    python scripts/fetch_model.py potion-retrieval-32M
"""

import hashlib
import os
import sys
import urllib.request
from pathlib import Path

MODELS = {
    "potion-base-8M": ("minishlab/potion-base-8M", "bf8b056651a2c21b8d2565580b8569da283cab23", {
        "tokenizer.json": "e67e803f624fb4d67dea1c730d06e1067e1b14d830e2c2202569e3ef0f70bb50",
        "model.safetensors": "f65d0f325faadc1e121c319e2faa41170d3fa07d8c89abd48ca5358d9a223de2",
    }),
    "potion-retrieval-32M": ("minishlab/potion-retrieval-32M", "6fc8051fab2a1e0ee76689cf08c853792ac285e7", {
        "tokenizer.json": "7d75cbc54318138807c401b0f0c9721117c628b39de8e8e0edb6cb17e0ee7d18",
        "model.safetensors": "07609e5bd33aad37900b3fd62f4ec96f6daec88ca4d46b9d8b928bfababf6ea0",
    }),
}


def main(name: str = "potion-base-8M") -> int:
    repo, revision, files = MODELS[name]
    base = os.environ.get("CLIPMIND_DATA_DIR") or os.path.join(os.environ["LOCALAPPDATA"], "clipmind")
    dest = Path(base) / "models" / name
    dest.mkdir(parents=True, exist_ok=True)
    for filename, expected in files.items():
        target = dest / filename
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
            print(f"ok      {filename}")
            continue
        url = f"https://huggingface.co/{repo}/resolve/{revision}/{filename}"
        print(f"fetch   {url}")
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = resp.read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            print(f"SHA-256 mismatch for {filename}: got {actual}, expected {expected}. Nothing written.")
            return 1
        tmp = target.with_suffix(".part")
        tmp.write_bytes(data)
        tmp.replace(target)
        print(f"ok      {filename}")
    print(f"model ready in {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
