import numpy as np
import pytest

from clipmind.search import Index


class ToyEmbedder:
    """Bag-of-letters embedder: enough to test ranking plumbing without the model."""

    dim = 26

    def embed(self, text):
        v = np.zeros(self.dim, dtype=np.float32)
        for ch in text.lower():
            if "a" <= ch <= "z":
                v[ord(ch) - 97] += 1
        n = np.linalg.norm(v)
        return v / n if n else v


@pytest.fixture
def index():
    idx = Index(ToyEmbedder())
    for i, text in enumerate(["docker compose up", "git rebase -i HEAD~3", "flight to mumbai PNR X7K2LQ"]):
        idx.add(i, text, 1_000 + i, idx.embedder.embed(text))
    return idx


def test_empty_query_lists_most_recent_first(index):
    assert [h.text for h in index.search("")][0] == "flight to mumbai PNR X7K2LQ"


@pytest.mark.parametrize("mode", ["hybrid", "keyword", "semantic"])
def test_exact_words_rank_first(index, mode):
    assert index.search("rebase", mode=mode)[0].text == "git rebase -i HEAD~3"


def test_pending_clips_are_searchable(index):
    hits = index.search("quarantined", pending=["a quarantined clip"])
    assert hits[0].text == "a quarantined clip" and hits[0].id is None


def test_adding_same_text_returns_old_id_for_deletion(index):
    assert index.add(9, "docker compose up", 5_000, index.embedder.embed("docker compose up")) == [0]
    assert index.ids.count(9) == 1 and 0 not in index.ids and len(index) == 3


def test_remove_and_clear(index):
    index.remove(1)
    assert len(index) == 2 and index.matrix.shape == (2, 26)
    matrix = index.matrix
    index.clear()
    assert len(index) == 0 and not matrix.any()  # old matrix zeroed in place


def test_building_a_10k_index_is_linear():
    """Regression for #6: re-stacking the matrix on every add made a 10k unlock take ~2 minutes."""
    import time

    idx = Index(ToyEmbedder())
    vec = np.ones(26, dtype=np.float32)
    start = time.perf_counter()
    for i in range(10_000):
        idx.add(i, f"clip {i}", i, vec)
    assert idx.matrix.shape == (10_000, 26)
    assert time.perf_counter() - start < 5  # was ~112 s before the fix


def test_duplicate_lookup_survives_remove(index):
    index.remove(0)
    assert index.add(7, "docker compose up", 9_000, index.embedder.embed("docker compose up")) == []
