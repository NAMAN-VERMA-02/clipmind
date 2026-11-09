# Security policy

clipmind handles clipboard data, so security reports are the most valuable issues this project gets.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting).

Useful details to include:
- what you can read, change or bypass, and from which position (see the adversaries in [THREAT_MODEL.md](THREAT_MODEL.md));
- Windows version and clipmind version;
- steps to reproduce. **Never include real secrets or real clipboard contents.** Use test values like the `4111 1111 1111 1111` test card.

You'll get an acknowledgement within 7 days. Fixes for confirmed issues ship in a patch release with credit, unless you'd rather stay anonymous.

## In scope

- a secret type that clipmind claims to filter but stores;
- a way to read stored history without a Windows Hello prompt;
- any network activity by clipmind;
- clip text reaching logs, crash reports, toasts or any file other than the encrypted DB;
- items that survive wipe-all or expiry in decryptable form.

## Out of scope

The items listed under "Out of scope" in [THREAT_MODEL.md](THREAT_MODEL.md), such as malware running as you while clipmind is unlocked.
