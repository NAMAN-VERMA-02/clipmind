# clipmind threat model

clipmind keeps a searchable history of what you copy. The clipboard is one of the most sensitive streams on a PC: passwords, OTPs, card numbers and API keys all pass through it. This document says what clipmind protects, against whom, and where it stops. It was written before the code, and it is updated whenever a design decision changes.

## Assets

1. **Clip history**: the text of each stored item, its embedding (embeddings can be partly inverted back to text, so they count as content), and the time it was copied.
2. **Secrets that pass through the clipboard**: these must never become part of asset 1.
3. **Key material**: the X25519 private key that opens the history, and the Windows Hello key that unwraps it.

## Design in one paragraph

Every stored item is a *sealed box*: a fresh X25519 key pair per item, ECDH with clipmind's public key, HKDF-SHA256, then AES-256-GCM. The private key is wrapped with a key derived from a **Windows Hello signature** (TPM-backed where the device has a TPM) and stored in **Windows Credential Manager** (DPAPI-protected), never in a plain file. The background listener only ever needs the public key. **While clipmind is locked the process cannot read its own history.** Unlocking needs a Hello prompt (PIN, face or fingerprint). clipmind locks itself after 10 minutes without use, and whenever Windows locks, sleeps or an RDP session disconnects.

## Adversaries and what clipmind does about them

| # | Adversary or risk | In scope? | Mitigation | Residual risk |
|---|---|---|---|---|
| A1 | Someone gets the disk, a backup or a copy of `history.db` (stolen laptop, cloned drive, sync tool) | Yes | Only ciphertext reaches disk. The DB lives in `%LOCALAPPDATA%` (never Roaming). Decrypting needs a Hello signature from this device and this user. | Item count and approximate DB size are visible. Each row's expiry hour is plaintext so expiry can run while locked. |
| A2 | Another Windows user on the same PC | Yes | Per-user `%LOCALAPPDATA%` ACLs; the Credential Manager entry and Hello key are per-user. | An administrator is out of scope (see O2). |
| A3 | Someone at your unlocked, unattended PC | Yes | After idle or a Windows lock, history needs Hello. Reading the DB and Credential Manager directly with a script doesn't help: the wrapped key needs a Hello signature. | Within the 10-minute unlocked window they can open the popup. Make the idle timeout shorter if this matters to you. |
| A4 | Malware running as you **while clipmind is locked** | Partly | It can't decrypt stored history without Hello. | It still sees every *new* copy live, just as clipmind does. It can trigger a Hello prompt for clipmind's key and hope you approve it. **A Hello prompt you didn't cause by opening clipmind is an attack: cancel it.** |
| A5 | Secrets captured by accident | Yes | Layered, first match drops: (1) the formats password managers set (`ExcludeClipboardContentFromMonitorProcessing`, `Clipboard Viewer Ignore`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0`), probed *before* the text is read; (2) a blocklist of source apps (password managers, Phone Link's OTP "Copy code", desktop authenticators); (3) private browser windows and banking-site window titles; (4) content filters for private keys, JWTs, API keys, high-entropy tokens, passwords, OTPs, card numbers (Luhn), Aadhaar (Verhoeff) and PAN, run on NFKC-normalised text with zero-width characters stripped; (5) a 120-second RAM quarantine: if the clipboard is cleared within that window (password managers auto-clear), the item is discarded and never touches disk. | Content-only password detection has a hard ceiling: human-chosen passwords and passphrases look like ordinary text. The README publishes measured false-negative rates per type. Private-window detection was verified live on 2026-11-09: Edge puts `[InPrivate]` in the window title; Chrome's title says nothing, but its accessibility (MSAA) name ends in `(Incognito)`, so clipmind reads that name for Chromium browsers. Firefox and Brave markers come from their known titles and were **not** verified (not installed on the test machine). |
| A6 | clipmind itself leaking data | Yes | **No network code**: an AST test bans network modules and network DLLs from the package, a test asserts the runtime dependency closure contains no HTTP client, and the whole test suite runs with sockets blocked. No telemetry. Logs hold decisions and lengths only, never clip text; a test fuzzes the pipeline and checks every log record. Crash reports are told to skip heap memory (`WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP)`). Nothing is shown in toasts or tray tooltips. | A Python-level socket block can't see native code. Mitigation: every dependency loads from local files only, and clipmind ships no tokenizer or hub library (its WordPiece tokenizer is pure Python). |
| A7 | Recovering deleted items from disk | Partly | SQLite `secure_delete=ON` zeroes freed pages; `journal_mode=DELETE` (no WAL copies); rows are ciphertext anyway. **Wipe-all** deletes every row, runs VACUUM, then deletes the Credential Manager entry and the Hello key. That is crypto-shredding: old ciphertext left anywhere becomes undecryptable. | On SSDs, overwriting a page doesn't guarantee the old flash cells are erased. Per-item delete relies on encryption, not on the overwrite. |
| A8 | Supply chain | Partly | Small runtime closure (`cryptography`, `numpy`, pywinrt for Hello). CI installs from a hash-pinned lockfile; `pip-audit` and Dependabot run; GitHub Actions are pinned to commit SHAs; CI has read-only permissions. The model is fetched by a separate script (not part of the app) at a pinned revision and checked against a pinned SHA-256. | pywinrt is community-maintained native code. A compromised maintainer of any dependency is outside what clipmind can stop. |
| A9 | Paste-back re-exposing an item | Yes | Text clipmind writes back carries `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0` and `CanUploadToCloudClipboard=0`, so Windows' own history and cloud clipboard don't store it again. | Apps that ignore those formats can still read it. |

## Out of scope (stated plainly)

- **O1. Malware running as you while clipmind is unlocked.** It can read clipmind's process memory. No clipboard tool can defend against this.
- **O2. Administrators, kernel drivers, physical attacks on a running machine** (DMA, cold boot).
- **O3. Memory forensics.** Python strings can't be zeroed, so decrypted text may linger in RAM, the pagefile or `hiberfil.sys` until overwritten. On lock clipmind zeroes the embedding matrix and drops its references; that's all Python allows.
- **O4. Screen capture and shoulder surfing.**
- **O5. RDP and VM clipboard redirection.** Copies arriving through `rdpclip.exe` carry no sensitive-format flags; only the content filters apply.
- **O6. Pasting into elevated (admin) windows.** Windows' UIPI blocks the synthetic Ctrl+V. The item stays on the clipboard so you can paste it yourself.
- **O7. Expiry while clipmind isn't running.** Nothing deletes old rows if the app never starts. Expiry runs first at every start, before unlock or capture. Rows stay encrypted the whole time.
- **O8. Windows' own clipboard history (Win+V) and cloud clipboard.** They store everything you copy, unfiltered. clipmind warns at startup when they're on. Turning them off is up to you (Settings → System → Clipboard).

## Decisions that trade security for usability

- **10-minute idle lock** (configurable). Shorter is safer; every unlock costs a Hello prompt.
- **Whole-item drop.** If any part of a clip looks like a secret, the whole clip is dropped rather than redacted. Partial redaction is easy to get wrong.
- **Fail closed when Hello is missing.** clipmind refuses to start without Windows Hello instead of falling back to a weaker key.
- **Losing Hello loses history.** A PIN reset or TPM clear makes old history undecryptable. For a 7-day history that's acceptable, and arguably a feature.
