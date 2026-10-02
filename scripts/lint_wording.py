#!/usr/bin/env python3
"""Wording check for ri-seal's public documents (standard library only).

Words that overstate what the tool does — 인증·공증·공인·법적 효력·보장·guarantee·notar*·certif*·투자자문·alpha·
자동매매·수익률 — may appear ONLY inside a negative sentence ("…이 아닙니다", "…하지 않습니다", "not …", "no …").
The unit checked is a sentence: a line is split at sentence ends (. ! ?) and at table-cell bars ( | ), so a negation
in one table cell does not excuse a word in another.

  python scripts/lint_wording.py                 # README·DISCLAIMER·PRIVACY·SECURITY (ko and en)
  python scripts/lint_wording.py FILE ...        # specific files
Exit 0 = clean, 1 = findings (printed as file:line: word — sentence).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FILES = ["README.md", "README.en.md", "DISCLAIMER.md", "DISCLAIMER.en.md", "PRIVACY.md", "PRIVACY.en.md",
                 "SECURITY.md", "SECURITY.en.md"]

BANNED = [
    ("인증", re.compile(r"인증")),
    ("공증", re.compile(r"공증")),
    ("공인", re.compile(r"공인")),
    ("법적 효력", re.compile(r"법적\s*효력")),
    ("보장", re.compile(r"보장")),
    ("guarantee", re.compile(r"guarantee", re.I)),
    ("notar", re.compile(r"notar", re.I)),
    ("certif", re.compile(r"certif", re.I)),
    ("투자자문", re.compile(r"투자\s*자문")),
    ("alpha", re.compile(r"\balpha\b", re.I)),
    ("자동매매", re.compile(r"자동\s*매매")),
    ("수익률", re.compile(r"수익률")),
]
NEGATION = re.compile(
    r"아닙니다|아니며|아니고|아니다|아님|아닌|않습니다|않으며|않고|않는|않음|않다|없습니다|없으며|없음|없는|못합니다|제외"
    r"|\bnot\b|\bno\b|\bnever\b|\bwithout\b|n't\b|\bnor\b|\bnone\b", re.I)
_SPLIT = re.compile(r"(?<=[.!?。])\s+|\s+\|\s+|^\s*\||\|\s*$")


def sentences(line: str) -> list[str]:
    return [s.strip() for s in _SPLIT.split(line) if s and s.strip()]


# Exact names that merely contain a banned stem (a Python package name). Removed before checking; nothing else is.
ALLOW_TOKENS = re.compile(r"`?\bcertifi\b`?")


def check_text(text: str) -> list[tuple[int, str, str]]:
    """[(line number, word, sentence)] for every banned word outside a negative sentence."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for s in sentences(ALLOW_TOKENS.sub(" ", line)):
            hits = [w for w, rx in BANNED if rx.search(s)]
            if hits and not NEGATION.search(s):
                out.extend((n, w, s) for w in hits)
    return out


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv] or [ROOT / f for f in DEFAULT_FILES]
    bad = 0
    for f in files:
        if not f.exists():
            print(f"{f}: missing")
            bad += 1
            continue
        for n, w, s in check_text(f.read_text("utf-8")):
            print(f"{f.name}:{n}: {w} — {s[:120]}")
            bad += 1
    print(f"lint_wording: {len(files)} file(s), {bad} finding(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
