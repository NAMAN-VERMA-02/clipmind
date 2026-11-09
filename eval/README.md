# Eval data

These files were committed **before** any filter or search code existed, so the git history shows they were never tuned against.

| File | What | Who wrote it |
|---|---|---|
| `near_misses_heldout.jsonl` | 392 *safe* clips that look like secrets (order IDs, IMEIs, public keys, code that mentions passwords, URLs with long IDs…). Every one must be **kept**. Used only for the held-out false-positive rate, never for tuning. | Hand-written. Public keys and certificates are real ones minted with `cryptography`. |
| `search_targets.jsonl` | 150 realistic clipboard items (T001–T150). | Hand-written. |
| `queries.jsonl` | 100 queries for T001–T100, typed `keyword` / `paraphrase` / `vague`. | Claude, without running any model. |
| `queries_naman.jsonl` | 50 queries for T101–T150. | Naman, blind: he saw only the targets, never the other queries or any results. |

Secret samples for false-negative rates are **not** stored here. The eval scripts mint them at run time from independent sources (real keys, real signed JWTs, published test card numbers, an open-source scanner's fixtures, SecLists), so they can't be shaped to fit the filters.

## Running the evals

```bash
python eval/filters_eval.py   # false negatives per secret type, false positives on safe text
python eval/search_eval.py    # Recall@k over 10,000 items, 2 models x 3 ranking modes
python eval/bench.py          # latency, unlock time, RAM, DB size on this machine
```

Results land in `eval/results/*.json`, each with the date, git SHA, Python version and machine. CI reruns the filter and search evals with `--check` and fails on a regression.

Independent sources (`eval/sources.py`) are fetched at run time from pinned commits and checked by SHA-256: detect-secrets' plugin test fixtures (Apache-2.0), SecLists' 10k common passwords (MIT), the EFF diceware wordlist. Published test card numbers from Stripe, Adyen and Razorpay docs are in `data/test_cards.json` with their source URLs. The OTP messages in `data/otp_messages.txt` were hand-written **after** the filters existed and are labelled as such.

The held-out near-misses were run once, after the filters were written, and the results are reported as-is. The weaknesses they exposed are filed as issues, not tuned away.
