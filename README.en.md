# ri-seal — receipts, seals and verification for AI-agent work

[한국어](README.md) · [Disclaimer](DISCLAIMER.en.md) · [Privacy](PRIVACY.en.md) · [Security](SECURITY.en.md) · [Contributing](CONTRIBUTING.en.md) · [Changelog](CHANGELOG.md)

ri-seal records **which files an AI agent (e.g. Claude Code) touched and when**, as a hash-chained receipt log, and signs it with your organisation's Ed25519 key. If a record that was **already sealed** is later edited or deleted, verification fails.

From 0.2 (personal edition) one screen shows what your agent did today and whether what it said matches the receipts — three pillars: security, efficiency, accuracy (`ri-seal status`, or `ri-seal ui` in a browser).

- **Tamper-evident (for sealed records):** each receipt carries the hash of the previous one; seals pin the chain head.
- **No content stored:** fingerprints only. By default (strict) every path name is stored as a keyed HMAC too; command text, session ids and sub-agent ids are always HMACs (not reversible without your secret pepper).
- **Local only:** no server, no telemetry. Only `ri-seal anchor` sends anything (the 32-byte seal hash and a random nonce — plus your IP, as with any request). Details: [PRIVACY.en.md](PRIVACY.en.md)
- **Never blocks the agent:** the hooks always exit 0 (failures go to `.riseal/hook_errors.log`).
- **Standards:** in-toto Statement v1, DSSE, OpenTimestamps, RFC 3161 — signatures and time proofs verify with public tools; the receipt/seal hash chains verify with ri-seal.

## What this tool does not guarantee (read before installing)
- Seals and external time anchors are technical evidence that records were in a given state at a given time and have not changed since. They are not a qualified electronic signature, qualified time-stamping, notarial or certification service, and they do not vouch for the truth, results, completeness or legal effect of the content.
- `status` numbers and the claim check are counts over record files on this computer. They do not rate the quality or results of the work.
- Records after the last seal, and a rewrite by an agent that can reach the key with your user rights, are not prevented (see "Limits and assumptions").
- This is not investment solicitation and not investment or legal advice. Free and provided AS IS; the full notice is in [DISCLAIMER.en.md](DISCLAIMER.en.md).

## Who can use it
| User | Possible? |
| --- | --- |
| Claude Code users | Yes — a few terminal commands (Python 3.10+, macOS / Linux) |
| Users of other AI agents | Partly — the automatic recording hook exists for Claude Code only. Seal, verify and the seal lines of `status` work; receipts and the claim check do not fill up by themselves |
| **People who do not use a terminal** | **Web verification only** — checking evidence you received at https://www.rootinsidegroup.com/trust. There is no installable app yet |

## Three-minute start
```bash
# 1) Install pinned to a commit. Replace <COMMIT> with the 40-character hash listed on the GitHub release page.
#    (installing from a branch name can install different code if the repository changes — SECURITY.en.md §5)
pip install "ri-seal[anchor] @ git+https://github.com/leekangyeop-cpu/ri-seal@<COMMIT>"
# or by release tag (a tag can be moved, so a commit pin is firmer):
# pip install "ri-seal[anchor] @ git+https://github.com/leekangyeop-cpu/ri-seal@v0.2.0"
# or download the release wheel, check it with shasum -a 256 -c SHA256SUMS, then pip install <wheel file>

# 2) Start
cd my-project
ri-seal init                  # signing key, kept outside the project in ~/.riseal/keys. Default privacy: strict
ri-seal install-claude-hook   # shows the change first, then registers two hooks:
                              #   PostToolUse → receipts / Stop → claim ↔ receipt check (measurement only, never blocks)
                              #   --no-claim-hook to skip the claim check, --dry-run to preview only
```
Then work with your agent as usual. Any time:
```bash
ri-seal status                # the three-pillar screen (--lang en / --lang ko)
ri-seal status --details      # file:line behind every number
ri-seal ui                    # the same screen in a browser — http://127.0.0.1:8765 (this computer only, Ctrl+C to stop)
```
At the end of the day:
```bash
ri-seal seal report.pdf && ri-seal anchor && ri-seal verify
ri-seal export evidence.zip
```
To stop using it:
```bash
ri-seal uninstall-claude-hook # removes exactly the two entries it installed (other hooks kept), preview first
```

## The three-pillar screen (`status`, `ui`)
Three sentences on top (one per pillar), the numbers, and a fixed footer — "This display shows the state of the records. It does not vouch for whether their content is right, or for any result."

| Pillar | Numbers | Counted from |
| --- | --- | --- |
| Security | receipts today · hidden names (HMAC) · seals · last seal · time anchors (none/pending/complete) · last verify · hook errors | `.riseal/receipts.jsonl`, `seals.jsonl`, `verify_log.jsonl`, `hook_errors.log` |
| Efficiency | files edited today · files edited 3+ times (rework) · sessions | Edit/Write rows in `receipts.jsonl` |
| Accuracy | claim hit rate = supported ÷ (supported + unsupported), last 30 days; unknown kept apart; `small_n` below 30 | `.riseal/claims.jsonl` |

- Three colours: green "nothing flagged", amber "incomplete" (anchors pending, never verified, rework present, small_n), red "look at this" (verify failed, unsupported claims today). **A state indicator, not a quality score.**
- Anchor state `complete` means every seal **has** an OpenTimestamps and an RFC 3161 receipt. Whether it is confirmed in a Bitcoin block is for `ots verify`.
- There is deliberately no combined score.

## Claim ↔ receipt check (measurement only)
When the agent finishes a reply (Claude Code `Stop` hook), sentences such as "12 passed", "fixed src/x.py", "verified", "done" are picked from the last reply **by fixed rules** and compared with **the same session's receipts**.

| Kind | supported | unsupported | unknown |
| --- | --- | --- | --- |
| test ("N passed") | a test run in the session that left a result summary line; if N was stated, some run passed exactly N | no test run, or no run passed N | only runs without a summary line (e.g. `pytest --version`, `--collect-only`), or the last run's summary reported failures/errors |
| fix / build ("fixed", "implemented") | the named file was edited (Edit/Write) | the named file was not touched (no file named: no edits at all) | only read, or edits without a named file |
| verify ("verified") | the named file was touched / no file named: a test run with a summary line exists | the named file was not touched | neither |
| complete ("done") | the named file was touched | the named file was not touched | no file named |
| review ("reviewed") | — | — | always (receipts hold no review trace) |
| negative / pending ("not verified", "pending") | — | — | always; left out of the rate |

- If a session mixes **several agents (main agent + sub-agents)** the claim is **unknown** — whose work it was cannot be told apart.
- **Never blocks.** Blocking would teach the agent to rephrase and the numbers would disappear. Exit code always 0; on failure one line on stderr.
- Strict mode stores an HMAC instead of the sentence.
- Limits: rules have false positives and misses. Receipts hold no command text, so the check sees "a test run happened and how many passed", not which test file ran. Sub-agent final reports (SubagentStop) are not checked.

## strict (default) vs normal
| | strict (`ri-seal init`) | normal (`ri-seal init --privacy normal`) |
| --- | --- | --- |
| paths in receipts | all HMAC, file fingerprints HMAC | readable unless sensitive-looking |
| sealed subject names | `hmac:…` (third parties check documents by SHA-256) | readable |
| claim records | sentence as HMAC, files as a count | first 200 characters and file names |
| recommended | records or bundles may be shown to others (default) | solo projects |

Projects created with 0.1 keep their setting. Files that look like secrets are left out of seals unless you pass `--allow-sensitive`. Record files are mode 600 in a 700 directory; the key and pepper live outside the project.

## Limits and assumptions — read this
- **Records after the last seal are not protected.** Seal at least once a day.
- **The agent runs as the same OS user as you.** It could read the key in `~/.riseal/keys` and rebuild receipts and seals. What reduces that risk: (1) run `ri-seal anchor` daily — Bitcoin / TSA time proofs cannot be re-created for the past even with the key; (2) keep `export` bundles somewhere the agent cannot reach (another machine, e-mail); (3) deny the agent access to `~/.riseal` in its permission settings (for Claude Code: `permissions.deny` with `Read(~/.riseal/**)` and `Bash(*riseal/keys*)`). None of them is a complete block.
- **Claim records are not covered by seals (0.2 limit).** `.riseal/claims.jsonl` is hash-chained, but a wholesale rewrite is not caught by `verify`. `status` numbers are counts over files on the same machine.
- **Automatic recording exists for Claude Code hooks only.**
- **Deleting seal rows from the tail is not caught by a local `verify`** (no key needed). Compare the seal count with an off-machine export or pass `--expect-seals N`.
- **Anchor rows are not signed.** `verify` only checks that each receipt is about the right seal; genuineness is for `ots verify` / `openssl ts -verify`.
- **Third parties must check the key fingerprint out of band.** `ri-seal verify` prints `pubkey_sha256`; compare it with the value the publisher posted on their own website/GitHub before trusting a bundle.
- Back up the private key and pepper (`~/.riseal/keys/`) offline; publish `pubkey_sha256` on at least two of your own channels.
- `ri-seal verify` exit codes: 0 clean · 2 chain intact but sealed files changed since · 1 chain/signature problem. Scripts must not treat 2 as clean.
- A seal shows the records looked like this at that time — not that they are correct.
- Not a qualified electronic signature or time-stamping service, and not legal or investment advice ([DISCLAIMER.en.md](DISCLAIMER.en.md)). macOS / Linux only.

## Release check
Each release ships `SHA256SUMS` for the sdist and wheel, plus an evidence bundle in which those files are sealed and anchored with ri-seal itself (`scripts/release.sh`). Check downloads with `shasum -a 256 -c SHA256SUMS`, the bundle with `ri-seal --dir <folder> verify`, and compare the key fingerprint below.

## Root Inside publisher key (out-of-band check)
Fingerprint of the Ed25519 key behind https://www.rootinsidegroup.com/trust — must equal the value shown there:
`sha256(raw 32-byte key) = 29b8c0462adbc700b147b634e18021fb58e34478272be5a56547d7aa4e7889d8` · check: `openssl base64 -d -in pubkey.pem | tail -c 32 | shasum -a 256`

Apache-2.0, free and as is · Root Inside Co., Ltd. — https://www.rootinsidegroup.com
