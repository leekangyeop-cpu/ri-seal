# ri-seal — receipts, seals and verification for AI-agent work

ri-seal records **which files an AI agent (e.g. Claude Code) touched and when**, as a hash-chained receipt log, and signs it with your organisation's Ed25519 key. If a record that was **already sealed** is later edited or deleted, verification fails.

- **Tamper-evident (for sealed records):** each receipt carries the hash of the previous one; seals pin the chain head.
- **No content stored:** only SHA-256 fingerprints of non-sensitive project files; command text, session ids and sensitive paths are stored as keyed HMACs (not reversible without your secret pepper).
- **Local only:** no server, no telemetry. Only `ri-seal anchor` sends anything (the 32-byte seal hash and a random nonce — plus your IP, as with any request).
- **Never blocks the agent:** the hook always exits 0 (failures go to `.riseal/hook_errors.log`).
- **Standards:** in-toto Statement v1, DSSE, OpenTimestamps, RFC 3161 — signatures and time proofs verify with public tools; the receipt/seal hash chains verify with ri-seal.

```bash
pip install "ri-seal[anchor] @ git+https://github.com/leekangyeop-cpu/ri-seal"   # not on PyPI yet — install from GitHub
ri-seal init && ri-seal install-claude-hook      # add --privacy strict to hide every path name; --shared for the team settings file
# ... work with your agent ...
ri-seal seal report.pdf && ri-seal anchor && ri-seal verify
ri-seal export evidence.zip
```

## Limits and assumptions — read this
- **Records after the last seal are not protected.** Seal at least once a day.
- **The agent runs as the same OS user as you.** It could read the key in `~/.riseal/keys` and rebuild receipts and seals. What reduces that risk: (1) run `ri-seal anchor` daily — Bitcoin / TSA time proofs cannot be re-created for the past even with the key; (2) keep `export` bundles somewhere the agent cannot reach (another machine, e-mail); (3) deny the agent access to `~/.riseal` in its permission settings (for Claude Code: `permissions.deny` with `Read(~/.riseal/**)` and `Bash(*riseal/keys*)`).
- **Deleting seal rows from the tail is not caught by a local `verify`** (no key needed). Compare the seal count with an off-machine export or pass `--expect-seals N`.
- **Anchor rows are not signed.** `verify` only checks that each receipt is about the right seal; genuineness is for `ots verify` / `openssl ts -verify`.
- **Third parties must check the key fingerprint out of band.** `ri-seal verify` prints `pubkey_sha256`; compare it with the value the publisher posted on their own website/GitHub before trusting a bundle.
- The three measures above (daily `anchor` together with off-machine `export` copies, and denying the agent access to the key folder) reduce the risk; none of them is a complete block.
- Back up the private key (`~/.riseal/keys/`) offline; publish `pubkey_sha256` on at least two of your own channels.
- What leaves the machine on `anchor`: the 32-byte seal hash and a random nonce (plus your IP, as with any request). Signatures and time proofs verify with public tools; the receipt/seal hash chains verify with ri-seal.
- `ri-seal verify` exit codes: 0 clean · 2 chain intact but sealed files changed since · 1 chain/signature problem. Scripts must not treat 2 as clean.
- A seal proves the records looked like this at that time — not that they are correct.
- Not a certification service and not legal advice. macOS / Linux only.

## Privacy
Sensitive-looking paths (`.env`, `*.pem`, `*.key`, `*secret*`, `*token*`, `.ssh/`, `.aws/`, … plus your `.risealignore`) are recorded only as an HMAC and their contents are never hashed. `--privacy strict` does this for every path. Files that look like secrets are left out of seals unless you pass `--allow-sensitive`. Record files are created with mode 600 in a 700 directory; the key and pepper live outside the project.

## Root Inside publisher key (out-of-band check)
Fingerprint of the Ed25519 key behind https://www.rootinsidegroup.com/trust — must equal the value shown there:
`sha256(raw 32-byte key) = 29b8c0462adbc700b147b634e18021fb58e34478272be5a56547d7aa4e7889d8` · check: `openssl base64 -d -in pubkey.pem | tail -c 32 | shasum -a 256`

Apache-2.0 · Root Inside Co., Ltd. — https://www.rootinsidegroup.com
