# Contributing — ri-seal

[한국어](CONTRIBUTING.md)

Contributions are welcome. Please follow these four rules.

## 1. DCO 1.1 sign-off (`Signed-off-by`)
Every commit must carry a sign-off line agreeing to the Developer Certificate of Origin 1.1 (https://developercertificate.org/). With it you state that you have the right to submit the contribution and agree to its publication under the project license.
```bash
git commit -s -m "what changed"     # appends Signed-off-by: Name <email>
```
Use your real name (or the name you normally use) and a reachable e-mail address. Commits without a sign-off cannot be accepted.

## 2. License of contributions
Anything you submit to this repository is contributed under the **Apache License 2.0** (Section 5 of the license). If you bring in code under another license, name its source and license in the pull request. Code that cannot be combined with Apache-2.0 will not be accepted.

## 3. No secrets, personal data or customer data
- Do **not** include API keys, passwords, tokens, private keys, peppers, real `.riseal/` records or real conversation transcripts.
- Do not use personal data (names, contact details, identification numbers …) or customer/company data as test material. Tests use synthetic data only; when a secret-looking string is needed, assemble it from pieces as the existing tests do.
- If you pushed something by mistake, report it right away through SECURITY.en.md. Removing it from history does not recall copies already cloned — revoke and replace the secret.

## 4. Tests come with the change
- Changes that add or alter behaviour come with tests; a fixed defect comes with a test that reproduces it.
- Before submitting, from the repository root:
```bash
python -m pytest -q
python scripts/lint_wording.py      # wording check for public documents
```
- Tests must not use the network (`anchor` is tested with a fake transport) and must not touch the user's home or real settings (use `tmp_path` and a replaced `HOME`).
- Please open an issue before adding a dependency. Today there is one: `cryptography`.

## Also
- Report security problems through [SECURITY.en.md](SECURITY.en.md), not a public issue.
- Documents avoid overstatement; what the tool does not show is written next to what it shows.
