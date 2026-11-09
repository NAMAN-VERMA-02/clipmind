# Eval data

These files were committed **before** any filter or search code existed, so the git history shows they were never tuned against.

| File | What | Who wrote it |
|---|---|---|
| `near_misses_heldout.jsonl` | 392 *safe* clips that look like secrets (order IDs, IMEIs, public keys, code that mentions passwords, URLs with long IDs…). Every one must be **kept**. Used only for the held-out false-positive rate, never for tuning. | Hand-written. Public keys and certificates are real ones minted with `cryptography`. |
| `search_targets.jsonl` | 150 realistic clipboard items (T001–T150). | Hand-written. |
| `queries.jsonl` | 100 queries for T001–T100, typed `keyword` / `paraphrase` / `vague`. | Claude, without running any model. |
| `queries_naman.jsonl` | 50 queries for T101–T150. | Naman, blind: he saw only the targets, never the other queries or any results. |

Secret samples for false-negative rates are **not** stored here. The eval scripts mint them at run time from independent sources (real keys, real signed JWTs, published test card numbers, an open-source scanner's fixtures, SecLists), so they can't be shaped to fit the filters.
