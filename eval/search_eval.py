"""Search eval: can you find the clip you meant among 10,000?

Corpus: the 150 hand-written targets + 9,850 distractors (8,850 CPython stdlib code snippets and 1,000 Python
docs prose, a different random sample from the filter eval). Every item gets a random
copy time so recency can't help. Queries are the labelled ones in eval/queries*.jsonl.

    python eval/search_eval.py          # run, write eval/results/search.json, print a table
    python eval/search_eval.py --check  # CI: fail if hybrid Recall@5 drops vs the committed file
"""

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

import corpus
from filters_eval import meta

from clipmind.embed import Embedder
from clipmind.search import MODES, Index

RESULTS = Path(__file__).parent / "results" / "search.json"
MODELS = ("potion-base-8M", "potion-retrieval-32M")
N_ITEMS, K = 10_000, 10
MARGIN = 0.02


def model_dir(name: str) -> Path:
    base = os.environ.get("CLIPMIND_DATA_DIR") or os.path.join(os.environ["LOCALAPPDATA"], "clipmind")
    return Path(base) / "models" / name


def build_corpus() -> tuple[list[tuple[int, str]], list[dict]]:
    targets = corpus.jsonl("search_targets.jsonl")
    n_dist = N_ITEMS - len(targets)
    pool = corpus.stdlib_prose(1000, seed=4) + corpus.stdlib_code(2 * n_dist, seed=3)
    seen, distractors = {t["text"] for t in targets}, []
    for d in pool:  # unique texts only: the index de-duplicates identical clips
        if d not in seen:
            seen.add(d)
            distractors.append(d)
    texts = [t["text"] for t in targets] + distractors[:n_dist]
    queries = corpus.jsonl("queries.jsonl")
    naman = Path(__file__).parent / "queries_naman.jsonl"
    if naman.exists():
        queries += corpus.jsonl(naman.name)
    target_row = {t["id"]: i for i, t in enumerate(targets)}
    for q in queries:
        q["row"] = target_row[q["target"]]
    return list(enumerate(texts)), queries


def rank(hits, row: int) -> int | None:
    return next((i for i, h in enumerate(hits, 1) if h.id == row), None)


def score(ranks: list[int | None]) -> dict:
    n = len(ranks)
    return {"n": n, "recall@1": round(sum(r == 1 for r in ranks if r) / n, 4),
            "recall@5": round(sum(r <= 5 for r in ranks if r) / n, 4),
            "recall@10": round(sum(r is not None for r in ranks) / n, 4),
            "mrr@10": round(sum(1 / r for r in ranks if r) / n, 4)}


def evaluate() -> dict:
    items, queries = build_corpus()
    created = random.Random(5).sample(range(N_ITEMS), N_ITEMS)
    out = {}
    for name in MODELS:
        emb = Embedder(model_dir(name))
        index = Index(emb)
        start = time.perf_counter()
        for row, text in items:
            index.add(row, text, created[row], emb.embed(text))
        embed_s = time.perf_counter() - start
        out[name] = {"embed_10k_items_s": round(embed_s, 2), "items_indexed": len(index), "modes": {}}
        for mode in MODES:
            ranks = [rank(index.search(q["query"], k=K, mode=mode), q["row"]) for q in queries]
            groups = {"all": ranks}
            for key in ("type", "author"):
                for value in sorted({q[key] for q in queries}):
                    groups[f"{key}={value}"] = [r for r, q in zip(ranks, queries, strict=True) if q[key] == value]
            out[name]["modes"][mode] = {g: score(r) for g, r in groups.items()}
    return {"meta": {**meta(), "command": "python eval/search_eval.py", "items": N_ITEMS,
                     "queries": len(queries)}, "models": out}


def table(res: dict) -> str:
    rows = ["| Model | Mode | Recall@1 | Recall@5 | Recall@10 | MRR@10 |", "|---|---|---:|---:|---:|---:|"]
    for model, r in res["models"].items():
        for mode, groups in r["modes"].items():
            a = groups["all"]
            rows.append(f"| {model} | {mode} | {a['recall@1']:.1%} | {a['recall@5']:.1%} | "
                        f"{a['recall@10']:.1%} | {a['mrr@10']:.3f} |")
    rows += ["", "Recall@5 by query type (hybrid):", ""]
    for model, r in res["models"].items():
        h = r["modes"]["hybrid"]
        rows.append(f"- {model}: " + ", ".join(f"{g.split('=')[1]} {s['recall@5']:.0%} (n={s['n']})"
                                                 for g, s in h.items() if g.startswith("type=")))
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    res = evaluate()
    print(table(res))
    if not args.check:
        RESULTS.parent.mkdir(exist_ok=True)
        RESULTS.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
        return 0
    base = json.loads(RESULTS.read_text(encoding="utf-8"))["models"]
    worse = [f"{m}: hybrid recall@5 {r['modes']['hybrid']['all']['recall@5']:.3f} < "
             f"{base[m]['modes']['hybrid']['all']['recall@5']:.3f}"
             for m, r in res["models"].items()
             if r["modes"]["hybrid"]["all"]["recall@5"] < base[m]["modes"]["hybrid"]["all"]["recall@5"] - MARGIN]
    print("\n".join(worse) or "no regression against eval/results/search.json")
    return 1 if worse else 0


if __name__ == "__main__":
    sys.exit(main())
