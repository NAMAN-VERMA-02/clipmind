"""Static sentence embeddings (model2vec "potion" models), pure Python + numpy.

A potion model is a token -> vector table; a text's embedding is the mean of its
token vectors, L2-normalised. The tokenizer is BERT WordPiece, reimplemented here
so clipmind doesn't ship the `tokenizers` package (which pulls in an HTTP client).
tests/test_embed.py checks token-for-token parity with `tokenizers` on a corpus.
"""

import json
import struct
import unicodedata
from pathlib import Path

import numpy as np

MAX_TOKENS = 512


def _is_punct(ch: str) -> bool:
    cp = ord(ch)
    if 33 <= cp <= 47 or 58 <= cp <= 64 or 91 <= cp <= 96 or 123 <= cp <= 126:
        return True
    return unicodedata.category(ch).startswith("P")


def _is_cjk(cp: int) -> bool:
    return (0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF or 0x20000 <= cp <= 0x2A6DF or 0x2A700 <= cp <= 0x2B73F
            or 0x2B740 <= cp <= 0x2B81F or 0x2B820 <= cp <= 0x2CEAF or 0xF900 <= cp <= 0xFAFF
            or 0x2F800 <= cp <= 0x2FA1F)


def _normalise(text: str) -> str:
    """BertNormalizer(clean_text, handle_chinese_chars, strip_accents (implied by lowercase), lowercase)."""
    out = []
    for ch in text:
        cp = ord(ch)
        if cp == 0 or cp == 0xFFFD:
            continue
        cat = unicodedata.category(ch)
        if ch in "\t\n\r" or cat == "Zs":
            out.append(" ")
        elif cat in ("Cc", "Cf"):
            continue
        elif _is_cjk(cp):
            out.append(f" {ch} ")
        else:
            out.append(ch)
    text = unicodedata.normalize("NFD", "".join(out))
    return "".join(c for c in text if unicodedata.category(c) != "Mn").lower()


def _pre_tokenise(text: str) -> list[str]:
    """BertPreTokenizer: split on whitespace, every punctuation char is its own word."""
    words, cur = [], []
    for ch in text:
        if ch.isspace():
            if cur:
                words.append("".join(cur))
                cur = []
        elif _is_punct(ch):
            if cur:
                words.append("".join(cur))
                cur = []
            words.append(ch)
        else:
            cur.append(ch)
    if cur:
        words.append("".join(cur))
    return words


class Embedder:
    def __init__(self, model_dir: Path):
        tok = json.loads((model_dir / "tokenizer.json").read_text(encoding="utf-8"))
        if tok["model"]["type"] != "WordPiece":
            raise ValueError("only WordPiece potion models are supported")
        self.vocab: dict[str, int] = tok["model"]["vocab"]
        self.unk = self.vocab.get(tok["model"].get("unk_token", "[UNK]"))
        self.prefix = tok["model"].get("continuing_subword_prefix", "##")
        self.max_word = tok["model"].get("max_input_chars_per_word", 100)
        self.table = _load_safetensors(model_dir / "model.safetensors")
        self.dim = self.table.shape[1]

    def tokenise(self, text: str) -> list[int]:
        ids = []
        for word in _pre_tokenise(_normalise(text)):
            ids.extend(self._wordpiece(word))
            if len(ids) >= MAX_TOKENS:
                break
        return ids[:MAX_TOKENS]

    def _wordpiece(self, word: str) -> list[int]:
        if len(word) > self.max_word:
            return [self.unk]
        out, start = [], 0
        while start < len(word):
            end = len(word)
            while end > start:
                piece = word[start:end] if start == 0 else self.prefix + word[start:end]
                if piece in self.vocab:
                    out.append(self.vocab[piece])
                    break
                end -= 1
            else:
                return [self.unk]
            start = end
        return out

    def embed(self, text: str) -> np.ndarray:
        ids = [i for i in self.tokenise(text) if i != self.unk]  # model2vec drops unknown tokens
        if not ids:
            return np.zeros(self.dim, dtype=np.float32)
        vec = self.table[ids].mean(axis=0, dtype=np.float32)
        norm = np.linalg.norm(vec)
        return vec / norm if norm else vec


def _load_safetensors(path: Path) -> np.ndarray:
    """Single-tensor F32/F16 safetensors file, memory-mapped (pages load on demand)."""
    with open(path, "rb") as f:
        (header_len,) = struct.unpack("<Q", f.read(8))
        header = json.loads(f.read(header_len))
    name = next(k for k in header if k != "__metadata__")
    meta = header[name]
    dtype = {"F32": np.float32, "F16": np.float16}[meta["dtype"]]
    begin, _ = meta["data_offsets"]
    return np.memmap(path, dtype=dtype, mode="r", offset=8 + header_len + begin, shape=tuple(meta["shape"]))
