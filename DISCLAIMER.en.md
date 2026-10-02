# Disclaimer — ri-seal

[한국어](DISCLAIMER.md)

This is a plain-language summary of the `LICENSE` (Apache License 2.0). Where they differ, **the `LICENSE` text governs**. This is not legal advice.

## 1. Free, as is
- ri-seal is open-source software published **free of charge** by Root Inside Co., Ltd.
- It is provided **"AS IS"**, without warranties or conditions of any kind, express or implied — including merchantability, fitness for a particular purpose, non-infringement, freedom from errors and uninterrupted operation (summary of Apache-2.0 §7).
- You decide whether and how to use it, and you carry the risks of doing so.

## 2. Limitation of liability
- Unless required by applicable law or agreed in writing, no contributor is liable for damages of any kind arising from the use of, or inability to use, this software (direct, indirect, special, incidental or consequential damages, loss of data, work stoppage …), even if advised of the possibility (summary of Apache-2.0 §8).
- Damage caused intentionally or by gross negligence is excluded from this limitation.
- The limitation also does not apply to the extent applicable law does not allow it.

## 3. What the tool does — and does not
- ri-seal's seals and external time anchors are **technical evidence** that records existed in a given state at a given time and have not changed since.
- ri-seal is not a qualified electronic signature, qualified time-stamping, notarial or certification service, and it does not vouch for the truth, results, completeness or legal effect of any content.

| Shows | Does not show |
| --- | --- |
| That the record files looked like this when they were sealed (signature, hash chain) | That the **content** of the records is right, or that the agent's work is correct |
| Whether sealed records were changed or removed (within what was sealed) | Records made **after** the last seal; seal rows cut from the tail (see README limits) |
| Whether an external time-anchor receipt is about this seal | Whether that receipt is genuine (check with `ots verify` / `openssl ts -verify`) |
| `status` numbers — counts over local record files | Quality, results or productivity of the work; any rating of a person or an agent |
| Claim check — whether a "done" sentence matches a trace in the receipts, by fixed rules | Whether the claim is true. The rules have false positives and misses |

## 4. Using it as evidence
Whether to present an `export` bundle in a dispute, audit or court, how to interpret and explain it, and where to submit it are **your decision and your responsibility.** Verification is done by you with public standard tools. Consult a lawyer or another professional if needed.

## 5. Not advice
ri-seal gives no investment solicitation and no investment, financial, legal, tax or accounting advice, and holds no opinion on any security. No output should be read as such advice. The package has no investment, securities or forecasting features.

## 6. Third-party services
- The public OpenTimestamps calendars, the FreeTSA (freetsa.org) time-stamping authority and the Bitcoin network are not operated or vouched for by Root Inside. They are subject to their own terms and availability.
- ri-seal contacts them **only when you run `ri-seal anchor`**. What is sent is listed in [PRIVACY.en.md](PRIVACY.en.md).

## 7. Cryptography
Only standard public algorithms are used (Ed25519 signatures, SHA-256 hashes, HMAC-SHA-256), through the public `cryptography` library and the Python standard library. There is no home-made cryptography. Checking import/export rules when you move or redistribute the software to another country is up to you.

## 8. Trademarks
The names and logos "Root Inside", "루트인사이드" and "ri-seal" are not licensed under Apache-2.0 (§6).

## 9. Governing law
This notice and the use of the software are governed by the laws of the Republic of Korea.

Contact: contact@rootinsidegroup.com
