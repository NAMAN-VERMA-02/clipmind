import inspect
import json
import os
from pathlib import Path

import numpy as np
import pytest

from clipmind.embed import MAX_TOKENS, Embedder

MODELS = Path(os.environ.get("CLIPMIND_DATA_DIR") or Path(os.environ["LOCALAPPDATA"]) / "clipmind") / "models"
EVAL = Path(__file__).resolve().parents[1] / "eval"


def model_dir(name):
    path = MODELS / name
    if not (path / "model.safetensors").exists():
        pytest.skip(f"model {name} not fetched (python scripts/fetch_model.py {name})")
    return path


def corpus():
    texts = [json.loads(line)["text"] for f in ("search_targets.jsonl", "near_misses_heldout.jsonl")
             for line in (EVAL / f).read_text(encoding="utf-8").splitlines()]
    texts += [json.loads(line)["query"] for line in (EVAL / "queries.jsonl").read_text(encoding="utf-8").splitlines()]
    texts += [inspect.getdoc(obj) or "" for obj in (json, os, Path, np.linalg, pytest)]
    texts += ["Café naïve résumé Ångström", "日本語のテキスト and 中文", "tab\there\r\nnew line", "\x00null� byte",
              "emoji 🎉👍 text", "a" * 150, "UPPER lower MiXeD", "hyphen-ated, punct!? (paren) [br] {cu} 'q' \"dq\"",
              "İstanbul ǅemal", "x" + " y" * 700, "", "   "]
    return texts


@pytest.mark.parametrize("name", ["potion-base-8M", "potion-retrieval-32M"])
def test_tokeniser_matches_huggingface_tokenizers(name):
    tokenizers = pytest.importorskip("tokenizers")
    path = model_dir(name)
    ref = tokenizers.Tokenizer.from_file(str(path / "tokenizer.json"))
    ours = Embedder(path)
    mismatches = [t for t in corpus() if ours.tokenise(t) != ref.encode(t, add_special_tokens=False).ids[:MAX_TOKENS]]
    assert not mismatches, f"{len(mismatches)} mismatches, first: {mismatches[0][:80]!r}"


def test_embeddings_are_normalised_and_meaningful():
    emb = Embedder(model_dir("potion-base-8M"))
    a, b, c = emb.embed("book a train ticket"), emb.embed("railway reservation"), emb.embed("chocolate cake recipe")
    assert abs(np.linalg.norm(a) - 1) < 1e-5
    assert a @ b > a @ c
    assert not emb.embed("").any()
