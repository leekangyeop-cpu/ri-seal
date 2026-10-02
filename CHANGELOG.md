# Changelog

## 0.2.0 — personal edition (unreleased)

Added
- `ri-seal status`: three pillars on one screen — security (receipts today, hidden names, seals, last seal, anchor state
  none/pending/complete, last verify), efficiency (files edited today, files edited 3+ times, sessions), accuracy
  (claim hit rate = supported / (supported + unsupported) over 30 days, unknown counted separately, `small_n` under 30).
  Three summary sentences on top, a fixed footer, `--lang ko|en`, `--details` (file:line behind every number), `--json`.
- Claim ↔ receipt self-check (measurement only): `ri-seal claim-hook`, registered as a Claude Code `Stop` hook by
  `install-claude-hook` (opt out with `--no-claim-hook`). Sentences such as "12 passed", "fixed src/x.py", "검증했습니다",
  "완료" are compared with the same session's receipts and appended to `.riseal/claims.jsonl` (hash-chained). Never
  blocks; always exits 0. Strict mode stores an HMAC instead of the sentence. Sessions mixing several agents → unknown.
- `ri-seal ui`: the same screen as a read-only page on 127.0.0.1 (standard library, no JavaScript, no outside requests,
  inline CSS, Host-header check). Default port 8765, Ctrl+C to stop.
- `ri-seal uninstall-claude-hook`: removes exactly the entries ri-seal installed; other hooks are kept. Install and
  uninstall print a diff preview first; `--dry-run` writes nothing.
- Receipts: for a command recognised as a test run, the class `test` and the pass/fail counts of its summary line;
  for sub-agent tool calls, an HMAC of the agent id. Still no command text, no output.
- `verify` (CLI) keeps a one-line result in `.riseal/verify_log.jsonl` for `status`.
- Documents: DISCLAIMER, PRIVACY, SECURITY (Korean and English), `scripts/release.sh` (tag → build → SHA256SUMS →
  self-seal → anchor → export; documented, pushes nothing).
- Legal notice alignment: DISCLAIMER (intent / gross-negligence carve-out, third-party services, evidence use,
  standard cryptography, governing law), NOTICE trademark line (Apache-2.0 §6), CONTRIBUTING (DCO 1.1 sign-off,
  Apache-2.0 contributions, no secrets or personal data, tests required), SECURITY (90-day coordinated disclosure,
  supported 0.2.x), README section on what the tool does not cover placed before installation.
- `scripts/lint_wording.py`: overstating words in public documents are allowed only inside negative sentences; run by
  the test suite.

Changed
- `ri-seal init` now defaults to `--privacy strict` (every path name stored only as an HMAC). `--privacy normal`
  restores the 0.1 default (`standard` is accepted as the old name). Existing projects keep their setting.
- `status` prints the three-pillar screen instead of a JSON line (`--json` for machines).
- Hook detection for install/uninstall is stricter (a command must end in `ri-seal hook` / `ri-seal claim-hook` exactly).

## 0.1.0 — 2026-10-01
First public release: receipts, Ed25519 seals (in-toto + DSSE), optional OpenTimestamps / RFC 3161 anchors, verify, export.
