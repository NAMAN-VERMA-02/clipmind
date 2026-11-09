"""In-memory search over decrypted history (exists only while unlocked).

Score = cosine(query, item) + 0.5 * share of query words found in the item
        + 0.3 if the whole query appears verbatim.
The weights were fixed before the eval ran, not tuned on it.
"""

import re
import time
from dataclasses import dataclass

import numpy as np

KEYWORD_WEIGHT, PHRASE_WEIGHT = 0.5, 0.3
MODES = ("hybrid", "semantic", "keyword")


@dataclass
class Hit:
    id: int | None  # None for a clip still in the RAM quarantine
    text: str
    created_ms: int
    score: float


def _terms(query: str) -> list[str]:
    return [t for t in re.findall(r"\w+", query.lower()) if len(t) > 1]


class Index:
    def __init__(self, embedder):
        self.embedder = embedder
        self.ids: list[int] = []
        self.texts: list[str] = []
        self.lower: list[str] = []
        self.created: list[int] = []
        self._vectors: list[np.ndarray] = []
        self._by_text: dict[str, int] = {}
        self._matrix: np.ndarray | None = None  # stacked lazily: re-stacking on every add was O(n^2) (#6)

    @property
    def matrix(self) -> np.ndarray:
        if self._matrix is None:
            self._matrix = (np.stack(self._vectors) if self._vectors
                            else np.zeros((0, self.embedder.dim), dtype=np.float32))
        return self._matrix

    def add(self, row_id: int, text: str, created_ms: int, embedding: np.ndarray) -> list[int]:
        """Add one item; returns ids of older copies of the same text, which the caller deletes."""
        old = self._by_text.get(text)
        if old is not None:
            self.remove(old)
        self.ids.append(row_id)
        self.texts.append(text)
        self.lower.append(text.lower())
        self.created.append(created_ms)
        self._vectors.append(np.array(embedding, dtype=np.float32))  # a copy: clear() zeroes it
        self._by_text[text] = row_id
        self._matrix = None
        return [] if old is None else [old]

    def remove(self, row_id: int) -> None:
        if row_id in self.ids:
            i = self.ids.index(row_id)
            self._by_text.pop(self.texts[i], None)
            for lst in (self.ids, self.texts, self.lower, self.created, self._vectors):
                del lst[i]
            self._matrix = None

    def clear(self) -> None:
        """Called on lock. Zeroes vectors in place; Python strings can't be zeroed, only dropped."""
        for array in [*self._vectors, *([self._matrix] if self._matrix is not None else [])]:
            array.fill(0)
        self.ids, self.texts, self.lower, self.created, self._vectors = [], [], [], [], []
        self._by_text, self._matrix = {}, None

    def __len__(self) -> int:
        return len(self.ids)

    def search(self, query: str, k: int = 20, pending: list[str] = (), mode: str = "hybrid") -> list[Hit]:
        now_ms = int(time.time() * 1000)
        ids = self.ids + [None] * len(pending)
        texts = self.texts + list(pending)
        lower = self.lower + [p.lower() for p in pending]
        created = self.created + [now_ms] * len(pending)
        if not texts:
            return []
        q = query.strip().lower()
        if not q:  # no query: most recent first
            order = sorted(range(len(texts)), key=lambda i: created[i], reverse=True)[:k]
            return [Hit(ids[i], texts[i], created[i], 0.0) for i in order]
        score = np.zeros(len(texts), dtype=np.float32)
        if mode in ("hybrid", "semantic"):
            matrix = self.matrix
            if pending:
                matrix = np.vstack([matrix, np.stack([self.embedder.embed(p) for p in pending])])
            score += matrix @ self.embedder.embed(query)
        if mode in ("hybrid", "keyword"):
            terms = _terms(q)
            if terms:
                score += KEYWORD_WEIGHT * np.array([sum(t in s for t in terms) / len(terms) for s in lower])
            score += PHRASE_WEIGHT * np.array([q in s for s in lower])
        age = np.array(created, dtype=np.float64)
        score += (1e-4 * (age - age.min()) / (np.ptp(age) + 1)).astype(np.float32)  # newer wins ties
        top = np.argsort(-score)[:k]
        return [Hit(ids[i], texts[i], created[i], float(score[i])) for i in top]
