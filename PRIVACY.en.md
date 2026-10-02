# Privacy and data — what ri-seal records and what it sends

[한국어](PRIVACY.md)

ri-seal has no server. It collects no usage statistics and sends no data to anyone, including Root Inside.

## 1. What leaves the machine
| When | What | Where |
| --- | --- | --- |
| **Only when you run `ri-seal anchor`** | the 32-byte seal fingerprint (SHA-256) | 2 public OpenTimestamps calendars (a.pool / b.pool.opentimestamps.org) |
| same | the 32-byte seal fingerprint + an **8-byte random nonce** (RFC 3161 request) | 1 time-stamping authority (default freetsa.org) |
| same (as with any internet request) | your **IP address**, `User-Agent: ri-seal/<version>`, TLS connection data | may be kept in those servers' logs |
| every other command (`init`, `hook`, `claim-hook`, `seal`, `verify`, `status`, `ui`, `export`, `install`/`uninstall-claude-hook`) | **nothing (0)** | — |

- File names, file contents, commands, conversation text and receipts are not sent, not even by `anchor`.
- `ri-seal ui` listens on 127.0.0.1 only and makes no outside requests (no external fonts, scripts or images in the page).
- `export` writes a file; it sends nothing. Who receives that file is up to you.
- Installing (`pip install … git+https://github.com/…`) is pip contacting GitHub, not ri-seal.

## 2. What stays on this machine
| Where | What | strict (default) | normal |
| --- | --- | --- | --- |
| `.riseal/receipts.jsonl` | one line per tool call: time, tool name, file path, file fingerprint, command HMAC, session HMAC, sub-agent HMAC, and for a test run the class `test` plus passed/failed **counts** | every path as HMAC, file fingerprints as HMAC | non-sensitive project paths and SHA-256 readable; sensitive-looking paths as HMAC |
| `.riseal/claims.jsonl` | one line per checked sentence: kind, supported/unsupported/unknown, evidence counts | sentence as **HMAC only**, files as a count | first 200 characters and the file names in it (HMAC instead when a sensitive-looking name appears) |
| `.riseal/seals.jsonl`, `proofs/` | signed seals, time-anchor receipts | sealed names as HMAC | names readable (secret-looking files left out automatically) |
| `.riseal/verify_log.jsonl` | counts from each `verify` run (problems, changed files) | same | same |
| `.riseal/hook_errors.log` | time and error class name when a hook failed | same | same |
| `.riseal/config.json`, `pubkey.pem` | key id, public key and fingerprint, creation time, privacy level | same | same |
| `~/.riseal/keys/<keyid>.pem`, `.pepper` | signing key and HMAC secret (mode 0600, outside the project) | same | same |
| `.claude/settings.local.json` (or `settings.json` with `--shared`) | the two hook entries; the first original kept as `.bak` | same | same |

- **Never recorded:** file contents, command text, tool output, conversation text, secret key values.
- For a test run only the numbers on the last summary line (`12 passed, 1 failed`) are kept.
- `claim-hook` reads only the **last reply** from the transcript file Claude Code already keeps on this machine (`transcript_path`). It does not copy or move that file.
- HMACs use a secret (pepper) kept outside the project; without it the original names cannot be recovered, even short ones.

## 3. strict vs normal
- From 0.2, `ri-seal init` defaults to **strict**. Keep it if records or `export` bundles may ever be shown to others.
- `ri-seal init --privacy normal` keeps non-sensitive paths readable — handy on a solo project when you want `status --details` to show which file was meant.
- Projects created with 0.1 keep their setting.

## 4. How to delete
```bash
ri-seal uninstall-claude-hook          # removes only the two hook entries (add --shared if installed that way); --dry-run to preview
rm -rf .riseal                          # this project's receipts, seals, claim records, proofs
rm ~/.riseal/keys/<keyid>.pem ~/.riseal/keys/<keyid>.pepper   # the key — irreversible
pip uninstall ri-seal
```
- Without the key you cannot make new seals. `export` bundles you already gave out still verify with the public key inside them.
- Without the pepper, strict-mode HMAC names cannot be resolved again (by you either).
- The 32-byte fingerprints sent by `anchor` stay in public calendars, Bitcoin blocks and the authority's records and cannot be deleted. They do not reveal the records.

Contact: contact@rootinsidegroup.com
