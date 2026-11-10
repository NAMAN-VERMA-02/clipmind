"""Secret-filter eval: false negatives per secret type, false positives on safe text.

    python eval/filters_eval.py          # run, write eval/results/filters.json, print a table
    python eval/filters_eval.py --check  # CI: fail if worse than the committed results
"""

import argparse
import datetime
import hashlib
import json
import platform
import random
import subprocess
import sys
from pathlib import Path

import corpus
import sources

from clipmind import __version__, filters

RESULTS = Path(__file__).parent / "results" / "filters.json"
FN_MARGIN, FP_MARGIN = 0.02, 0.005  # CI tolerance (CI's CPython patch version may differ)


def build() -> tuple[dict, dict]:
    rnd = random.Random(20261110)
    ds = sources.detect_secrets_samples()
    positives = {
        "private_key (real keys: cryptography + ssh-keygen)": corpus.private_keys(),
        "jwt (really signed: HS/RS/ES/EdDSA)": corpus.jwts(rnd),
        "api_key (detect-secrets fixtures, 24 plugins)": [(p, t) for p, t, flag in ds if flag],
        "card (187 published test numbers x 4 formats)": corpus.cards(),
        "otp (hand-written messages + bare codes)": corpus.otp_messages(rnd),
        "aadhaar (synthetic, Verhoeff-valid)": corpus.aadhaar(rnd),
        "pan (synthetic, valid format)": corpus.pans(rnd),
        "password": corpus.passwords(rnd),
        "random token (synthetic)": corpus.random_tokens(rnd),
    }
    negatives = {
        "held-out near-misses (392, hand-written)": [(r["kind"], r["text"])
                                                     for r in corpus.jsonl("near_misses_heldout.jsonl")],
        "CPython stdlib code (4,000 snippets)": [("code", t) for t in corpus.stdlib_code(4000, seed=1)],
        "Python docs prose (1,000 paragraphs)": [("prose", t) for t in corpus.stdlib_prose(1000, seed=2)],
    }
    # detect-secrets' per-plugin negatives are mostly MALFORMED secrets (a GitHub token is a negative in the
    # GitLab test, a Discord token with one char changed...). Dropping those is fine for a clipboard, so they
    # are reported on their own and not counted as false positives.
    shaped = {"detect-secrets per-plugin negatives (secret-shaped)": [(p, t) for p, t, flag in ds if not flag]}
    return positives, negatives, shaped


def evaluate(groups: dict, secret: bool, redact: bool = False) -> dict:
    out = {}
    for group, samples in groups.items():
        by_variant, flagged = {}, []
        for variant, text in samples:
            reason = filters.check(text)
            v = by_variant.setdefault(variant, {"n": 0, "dropped": 0})
            v["n"] += 1
            v["dropped"] += reason is not None
            if (reason is None and secret) or (reason is not None and redact):  # secret-shaped: fingerprint only
                flagged.append({"variant": variant, "preview": text[:4] + "…", "len": len(text),
                                "sha256": hashlib.sha256(text.encode()).hexdigest()[:16]})
            elif reason is not None and not secret:  # a false alarm on safe text
                flagged.append({"variant": variant, "detector": reason, "text": text[:160]})
        n, dropped = len(samples), sum(v["dropped"] for v in by_variant.values())
        rate = (n - dropped) / n if secret else dropped / n
        out[group] = {"n": n, "dropped": dropped, ("fn_rate" if secret else "fp_rate"): round(rate, 4),
                      "by_variant": by_variant, ("missed" if secret else "false_alarms"): flagged}
    return out


def meta() -> dict:
    sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    return {"date": datetime.date.today().isoformat(), "git": sha, "clipmind": __version__,
            "python": platform.python_version(), "platform": platform.platform(),
            "command": "python eval/filters_eval.py"}


def table(res: dict) -> str:
    rows = ["| Secret type (source) | Samples | Dropped | False-negative rate |", "|---|---:|---:|---:|"]
    for g, r in res["secrets"].items():
        rows.append(f"| {g} | {r['n']} | {r['dropped']} | {r['fn_rate']:.1%} |")
        if 2 <= len(r["by_variant"]) <= 4:  # a pooled rate hides groups that behave differently (e.g. OTP)
            rows += [f"| &nbsp;&nbsp;- {v} | {s['n']} | {s['dropped']} | {(s['n'] - s['dropped']) / s['n']:.1%} |"
                     for v, s in r["by_variant"].items()]
    rows += ["", "| Safe text | Samples | Dropped | False-positive rate |", "|---|---:|---:|---:|"]
    rows += [f"| {g} | {r['n']} | {r['dropped']} | {r['fp_rate']:.1%} |" for g, r in res["safe"].items()]
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    positives, negatives, shaped = build()
    res = {"meta": meta(), "secrets": evaluate(positives, True), "safe": evaluate(negatives, False),
           "secret_shaped_negatives": evaluate(shaped, False, redact=True)}
    print(table(res))
    if not args.check:
        RESULTS.parent.mkdir(exist_ok=True)
        RESULTS.write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        return 0
    base = json.loads(RESULTS.read_text(encoding="utf-8"))
    worse = [f"{g}: FN {r['fn_rate']:.3f} > {base['secrets'][g]['fn_rate']:.3f}"
             for g, r in res["secrets"].items() if r["fn_rate"] > base["secrets"][g]["fn_rate"] + FN_MARGIN]
    worse += [f"{g}: FP {r['fp_rate']:.3f} > {base['safe'][g]['fp_rate']:.3f}"
              for g, r in res["safe"].items() if r["fp_rate"] > base["safe"][g]["fp_rate"] + FP_MARGIN]
    print("\n".join(worse) or "no regression against eval/results/filters.json")
    return 1 if worse else 0


if __name__ == "__main__":
    sys.exit(main())
