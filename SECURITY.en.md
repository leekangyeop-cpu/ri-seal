# Security — ri-seal

[한국어](SECURITY.md)

## 1. Reporting a vulnerability
- **Please do not open a public issue.** E-mail contact@rootinsidegroup.com with `[ri-seal security]` in the subject: how to reproduce, affected version or commit, and a minimal example if you can.
- If GitHub private vulnerability reporting (Security → Report a vulnerability) is enabled on the repository, you can use that instead.
- We reply as soon as we have looked at it and record the fix in the CHANGELOG (crediting you if you wish).
- **90-day coordinated disclosure**: we aim to ship a fix within 90 days of the report and ask that neither side publish details before then. After 90 days the reporter may publish, fixed or not. A shorter or longer schedule can be agreed. As a free project we cannot promise a fix within that window.
- **Supported versions**: 0.2.x (the latest release). 0.1.x gets no security fixes — please upgrade to 0.2.x.

## 2. Keeping the key
- The signing key and the pepper are created in `~/.riseal/keys/` with mode 0600, **outside the project**. `seal` refuses a key with looser permissions.
- Keep an **offline copy** of both (encrypted USB, password manager, paper). Lose the key and you cannot make new seals; lose the pepper and strict-mode names cannot be resolved again.
- Publish the key fingerprint (`pubkey_sha256`) on **at least two** of your own channels (website, GitHub). Third parties compare against it to reject forged bundles.
- If you suspect the key leaked: create a new key with `ri-seal init` in a fresh project folder, replace the published fingerprint and announce the date. Earlier seals that were anchored (`anchor`) keep their evidence of "existed before that time".

## 3. The agent can reach the key
- The agent runs as **the same OS user** as you. It could read `~/.riseal/keys` and rebuild receipts and seals. ri-seal cannot prevent this.
- What **reduces** the risk (none is a complete block):
  1. `ri-seal anchor` daily — external time receipts cannot be re-created for the past, even with the key.
  2. Keep `export` bundles where the agent cannot reach (another machine, e-mail) — a rebuilt history will not match them.
  3. Deny the agent the key folder — for Claude Code, `permissions.deny` with `Read(~/.riseal/**)` and `Bash(*riseal/keys*)`. Settings can be bypassed; treat them as a secondary measure.
- The hooks **never stop the agent** (exit code always 0). ri-seal records; it does not block.

## 4. The local page (`ri-seal ui`)
- Bound to 127.0.0.1 only (fixed in code, no option). Other devices on your network cannot open it.
- Read-only: GET only; no forms, no write actions, no JavaScript. Zero outside requests (Content-Security-Policy `default-src 'none'`).
- Requests whose Host header is not 127.0.0.1/localhost are refused (stops other websites from reading it via DNS rebinding).
- Shows counts and `file:line` references only — no claim sentences, no path names.
- Other programs on the same computer (including other users) can connect to that port; the design assumes it shows counts only. Stop it with `Ctrl+C` when you do not need it.

## 5. Supply chain — is the code you install the code that was published?
- Prefer a **commit-pinned install**: `pip install "ri-seal[anchor] @ git+https://github.com/leekangyeop-cpu/ri-seal@<40-character commit hash>"`. The hash is listed on the GitHub release page. Installing from a branch name (`main`) can install different code if the repository changes.
- For every release (`scripts/release.sh`):
  1. a signed tag `vX.Y.Z`
  2. sdist and wheel, plus `SHA256SUMS`
  3. those files **sealed with ri-seal itself** and anchored with `anchor`
  4. the verification bundle (zip) attached to the release
- Checking what you downloaded: `shasum -a 256 -c SHA256SUMS` → unzip the attached bundle and run `ri-seal --dir <folder> verify` → compare the printed `pubkey_sha256` with the Root Inside key fingerprint in the README.
- One dependency, `cryptography` (optional `certifi`). No home-made cryptography (Ed25519, SHA-256 and HMAC come from the standard library and cryptography).

## 6. Known limits (summary)
See "Limits and assumptions" in the README — records after the last seal are not protected, seal rows cut from the tail are not caught by a local `verify`, anchor rows are not signed, macOS / Linux only.
