"""Claim ↔ receipt self-check — measurement only, never blocking.

At the end of each agent turn (Claude Code `Stop` hook) the agent's last message is split into clauses. Clauses that
claim something was done ("12 passed", "fixed src/x.py", "검증했습니다", "완료") are compared with this session's
receipts and appended to `.riseal/claims.jsonl` as supported / unsupported / unknown.

Rules, not a language model. The rules are crude on purpose — they are readable and the same every time — and they
have false positives and misses (see README). A "supported" row only means a matching trace exists in the receipts
(a file was edited, a test command ran); it does not mean the claim is true.

Privacy: in strict mode the clause text is stored only as an HMAC; in normal mode the first 200 characters are stored,
unless the clause names a sensitive-looking path, in which case it is stored as an HMAC too.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from .core import EDIT_TOOLS, Project, _patterns, append, is_sensitive, keyed, now_iso, pepper, read_rows

MAX_CLAUSES = 60
MAX_TRANSCRIPT_BYTES = 8 << 20

_FENCE = re.compile(r"```.*?(?:```|\Z)", re.S)
_BULLET = re.compile(r"^\s*(?:[-*+•]|\d+[.)])\s+")
_SPLIT = re.compile(r"(?<=[.!?。])\s+|;\s*|\s+—\s+|\s+\|\s+|\|\s*$|^\s*\||\s*→\s*(?!\d)|,\s+")

KIND_RULES: list[tuple[str, re.Pattern]] = [
    ("test", re.compile(r"\b\d+\s*(?:tests?\s+)?passed\b|\d+\s*개?\s*통과|테스트\s*\d+\s*(?:개\s*)?통과"
                        r"|pytest[^.]*?(?:통과|passed|성공)|\b(?:all\s+)?tests?\s+pass(?:ed|es)?\b", re.I)),
    ("review", re.compile(r"검수했|검수\s*완료|검수\s*통과|\breviewed\b", re.I)),
    ("fix", re.compile(r"수리했|수리\s*완료|수리함|고쳤|수정했|\bfixed\b", re.I)),
    ("build", re.compile(r"구축했|구현했|추가했|\bimplemented\b|\bbuilt\b|\badded\b", re.I)),
    ("verify", re.compile(r"검증|확인했|확인됨|확인\s*완료|\bverified\b|\bconfirmed\b", re.I)),
    ("complete", re.compile(r"완료|끝냈|마쳤|\bdone\b|\bcompleted\b|\bpassed\b|통과", re.I)),
]
_NEGATIVE = re.compile(
    r"못\s*했|않았|않음|안\s*했|미검증|미확인|미실행|필요|예정|대기|검수\s*전|금지|불가|실패|아직"
    r"|\bnot\s+(?:yet|verified|run|tested|checked)\b|\bpending\b|\bfailed\b|\bunverified\b|\btodo\b"
    r"|\bcould\s+not\b|\bdid\s+not\b|\bdidn't\b|\bcannot\b|\bunable\b|\bwill\b|\bnext\b", re.I)
_ZERO_FAIL = re.compile(r"\b0\s+failed\b|\b0\s+errors?\b|실패\s*0|0\s*실패", re.I)
_FILE = re.compile(r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.(?:py|ya?ml|json|jsonl|md|sh|toml|cfg|ini|js|mjs|ts|tsx|jsx|go|rs"
                   r"|java|kt|rb|php|c|h|cc|cpp|hpp|cs|swift|txt|html|css|sql))\b")
_N_PASSED = re.compile(r"\b(\d+)\s*(?:tests?\s+)?passed\b|(\d+)\s*개?\s*통과|테스트\s*(\d+)\s*(?:개\s*)?통과", re.I)


# ── extraction ───────────────────────────────────────────────────────

def clauses(text: str) -> list[str]:
    text = _FENCE.sub(" ", text or "")
    out: list[str] = []
    for line in text.splitlines():
        line = _BULLET.sub("", line).strip()
        if not line:
            continue
        for c in _SPLIT.split(line):
            c = (c or "").strip(" *_`#>")
            if c and c not in out:
                out.append(c)
    return out


def classify(clause: str) -> str | None:
    neg_text = _ZERO_FAIL.sub(" ", clause)
    kind = next((k for k, rx in KIND_RULES if rx.search(clause)), None)
    if kind is None:
        return None
    return "negative" if _NEGATIVE.search(neg_text) else kind


def extract(text: str) -> list[dict]:
    """[{clause, kind, files, n_passed}] — kind ∈ test|review|fix|build|verify|complete|negative."""
    out = []
    for c in clauses(text):
        kind = classify(c)
        if kind is None:
            continue
        files = sorted(set(_FILE.findall(c)))
        m = _N_PASSED.search(c)
        n = next((int(g) for g in m.groups() if g), None) if m else None
        out.append({"clause": c, "kind": kind, "files": files, "n_passed": n})
        if len(out) >= MAX_CLAUSES:
            break
    return out


# ── the last assistant message of a Stop event ──────────────────────

def _text_of(entry: dict) -> str:
    msg = entry.get("message") if isinstance(entry.get("message"), dict) else entry
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def last_assistant_text(payload: dict) -> str:
    """The final reply of the main thread: `last_assistant_message` if the agent sends it, otherwise the assistant text
    entries after the last user entry in the transcript (JSONL). Side-chain (sub-agent) entries are ignored."""
    direct = payload.get("last_assistant_message")
    if isinstance(direct, str) and direct.strip():
        return direct
    tp = payload.get("transcript_path")
    if not isinstance(tp, str) or not tp:
        return ""
    p = Path(tp).expanduser()
    if not p.is_file():
        return ""
    with open(p, "rb") as f:
        size = p.stat().st_size
        if size > MAX_TRANSCRIPT_BYTES:
            f.seek(size - MAX_TRANSCRIPT_BYTES)
            f.readline()                                  # drop the partial first line
        raw = f.read().decode("utf-8", errors="replace")
    tail: list[str] = []
    last_with_text = ""
    for line in raw.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or e.get("isSidechain"):
            continue
        t = e.get("type") or (e.get("message") or {}).get("role")
        if t == "user":
            tail = []
        elif t == "assistant":
            txt = _text_of(e)
            if txt.strip():
                tail.append(txt)
                last_with_text = txt
    return "\n".join(tail) if tail else last_with_text


# ── judging against receipts ─────────────────────────────────────────

def _session_rows(proj: Project, session_hmac: str) -> list[dict]:
    return [r for r in read_rows(proj.receipts) if (r.get("event") or {}).get("session_hmac") == session_hmac]


SKIP_DIRS = {".git", ".riseal", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
             "dist", "build", ".next", "target"}
MAX_INDEX_FILES = 50_000                              # keep the Stop hook well inside its timeout on large trees


class NameIndex(dict):
    """file name → project-relative paths. `truncated` is True when the walk stopped at MAX_INDEX_FILES — then a name that
    is not found may still exist, and a claim about it must not be called unsupported."""
    truncated = False


def basename_index(root: Path, limit: int = MAX_INDEX_FILES) -> NameIndex:
    """One bounded walk (skips vendor/build folders, stops after `limit` files and marks the index truncated)."""
    out = NameIndex()
    n = 0
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if n >= limit:
                out.truncated = True
                return out
            out.setdefault(f, []).append(os.path.relpath(os.path.join(d, f), root))
            n += 1
    return out


def _path_keys(proj: Project, pep: bytes, name: str, index: dict[str, list[str]] | None = None) -> set[str]:
    """Every way a receipt could have recorded this file: relative path, its HMAC, and (outside project) the HMAC of the
    absolute path. A bare file name is matched against project files with that name (via `index`)."""
    keys: set[str] = set()
    p = Path(name)
    cands: list[str] = []
    if p.is_absolute():
        keys.add(keyed(pep, str(p)))
        try:
            cands.append(str(p.resolve().relative_to(proj.root)))
        except (ValueError, OSError):
            pass
    else:
        cands.append(str(Path(name)))
        if "/" not in name:
            cands.extend((index if index is not None else basename_index(proj.root)).get(name, []))
    for c in cands:
        keys.add(c)
        keys.add(keyed(pep, c))
        keys.add(keyed(pep, str(proj.root / c)))
    return keys


def _touched(rows: list[dict], keys: set[str]) -> list[dict]:
    out = []
    for r in rows:
        for it in (r.get("event") or {}).get("paths") or []:
            if it.get("path") in keys or it.get("path_hmac") in keys:
                out.append(r)
                break
    return out


def judge(proj: Project, pep: bytes, rows: list[dict], claim: dict,
          index: dict[str, list[str]] | None = None) -> tuple[str, dict]:
    """(status, evidence). rows = the session's receipts."""
    agents = {(r.get("event") or {}).get("agent_hmac") for r in rows}
    ev: dict = {"session_receipts": len(rows), "n_agents": len(agents)}
    kind = claim["kind"]
    if kind == "negative":
        return "unknown", {**ev, "reason": "negative_or_pending_clause"}
    if not rows:
        return "unknown", {**ev, "reason": "no_receipts_in_session"}
    if len(agents) > 1:                               # main thread + sub-agents (or several sub-agents): whose work is it?
        return "unknown", {**ev, "mixed_agents": True, "reason": "mixed_agents"}
    edits = [r for r in rows if (r.get("event") or {}).get("tool") in EDIT_TOOLS]
    tests = [r for r in rows if (r.get("event") or {}).get("cmd_class") == "test"]
    counts = [r["event"]["test_counts"] for r in tests if isinstance(r["event"].get("test_counts"), dict)]
    ev.update({"edit_calls": len(edits), "test_runs": len(tests), "test_runs_with_counts": len(counts)})
    keys: set[str] = set()
    for f in claim.get("files") or []:
        keys |= _path_keys(proj, pep, f, index)
    named = bool(claim.get("files"))
    touched = _touched(rows, keys) if named else []
    touched_edit = [r for r in touched if (r.get("event") or {}).get("tool") in EDIT_TOOLS]
    # a bare file name that the (truncated) index could not resolve may exist after all → never "unsupported" for it
    unresolved = bool(index is not None and getattr(index, "truncated", False)
                      and any("/" not in f and not Path(f).is_absolute() and f not in index for f in claim.get("files") or []))
    if named:
        ev.update({"named_files": len(claim["files"]), "touched_calls": len(touched), "touched_edit_calls": len(touched_edit)})
        if unresolved:
            ev["index_truncated"] = True
    not_touched = ("unknown", {**ev, "reason": "index_incomplete_name_not_found"}) if unresolved else \
                  ("unsupported", {**ev, "reason": "named_file_not_touched"})

    if kind == "test":
        if not tests:
            return "unsupported", {**ev, "reason": "no_test_run_in_session"}
        if not counts:                                # e.g. `pytest --version` / `--collect-only`: ran, but no result line
            return "unknown", {**ev, "reason": "test_run_without_summary"}
        if counts[-1].get("failed") or counts[-1].get("errors"):
            return "unknown", {**ev, "reason": "last_test_run_reported_failures"}
        n = claim.get("n_passed")
        if n is not None:
            match = any(c.get("passed") == n for c in counts)
            ev["count_match"] = match
            if not match:
                return "unsupported", {**ev, "reason": "claimed_count_not_in_any_run"}
        return "supported", {**ev, "reason": "test_run_in_session"}
    if kind == "review":
        return "unknown", {**ev, "reason": "no_review_evidence_source"}
    if kind in ("fix", "build"):
        if named:
            if touched_edit:
                return "supported", {**ev, "reason": "named_file_edited"}
            if touched:
                return "unknown", {**ev, "reason": "named_file_touched_not_edited"}
            return not_touched
        if not edits:
            return "unsupported", {**ev, "reason": "no_edits_in_session"}
        return "unknown", {**ev, "reason": "no_file_named"}
    if kind == "verify":
        if named:
            return ("supported", {**ev, "reason": "named_file_touched"}) if touched else not_touched
        if counts:
            return "supported", {**ev, "reason": "test_run_in_session"}
        return "unknown", {**ev, "reason": "test_run_without_summary" if tests else "no_file_named_no_test_run"}
    # complete
    if named:
        return ("supported", {**ev, "reason": "named_file_touched"}) if touched else not_touched
    return "unknown", {**ev, "reason": "no_file_named"}


def record(proj: Project, text: str, session_id: str | None, source: str = "hook") -> list[dict]:
    """Extract, judge and append. Returns the rows written. Skips a message already recorded for this session."""
    pep = pepper(proj)
    strict = proj.cfg().get("privacy") == "strict"
    pats = _patterns(proj)
    sess_h = keyed(pep, str(session_id))[:32] if session_id else None
    msg_h = keyed(pep, "msg:" + (text or ""))[:32]
    prior = read_rows(proj.claims)
    if any(r.get("message_hmac") == msg_h and r.get("session_hmac") == sess_h for r in prior[-500:]):
        return []
    rows = _session_rows(proj, sess_h) if sess_h else []
    claims = extract(text)
    index = basename_index(proj.root) if any("/" not in f for c in claims for f in c["files"]) else NameIndex()
    out = []
    for c in claims:
        status, ev = judge(proj, pep, rows, c, index) if sess_h else ("unknown", {"reason": "no_session_id"})
        sensitive = any(is_sensitive(f, pats) for f in c["files"])
        row = {"kind": c["kind"], "status": status, "evidence": ev, "session_hmac": sess_h, "message_hmac": msg_h,
               "n_passed_claimed": c["n_passed"], "source": source, "privacy": "strict" if strict else "standard"}
        if strict or sensitive:
            row["claim_hmac"] = keyed(pep, "claim:" + c["clause"])
            row["n_files"] = len(c["files"])
        else:
            row["claim"] = c["clause"][:200]
            row["files"] = c["files"]
        out.append(append(proj.claims, lambda prev, seq, row=row: {"seq": seq, "prev": prev, "ts": now_iso(), **row}))
    return out


def summarize(proj: Project, days: int = 30, now: datetime | None = None) -> dict:
    now = (now or datetime.now().astimezone())
    since = now - timedelta(days=days)
    rows = []
    for n, r in numbered(proj.claims):
        try:
            t = datetime.fromisoformat(r["ts"])
        except (KeyError, ValueError, TypeError):
            continue
        if since <= t <= now + timedelta(minutes=1):
            rows.append((n, r, t))
    by = {"supported": [], "unsupported": [], "unknown": [], "negative": []}
    today = []
    for n, r, t in rows:
        key = "negative" if r.get("kind") == "negative" else r.get("status")
        if key in by:
            by[key].append(n)
        if t.astimezone(now.tzinfo).date() == now.date():
            today.append(n)
    s, u = len(by["supported"]), len(by["unsupported"])
    den = s + u
    return {"window_days": days, "supported": s, "unsupported": u, "unknown": len(by["unknown"]),
            "negative": len(by["negative"]), "denominator": den, "hit_rate": (s / den) if den else None,
            "small_n": den < 30, "claims_today": len(today),
            "unsupported_today": sum(1 for n, r, t in rows if n in set(today) and r.get("status") == "unsupported"
                                     and r.get("kind") != "negative"),
            "_lines": {k: v for k, v in by.items()}, "_lines_today": today}


def numbered(path: Path):
    """(1-based physical line number, row) for every valid JSON-object line — for `status --details`."""
    if not path.exists():
        return
    for n, line in enumerate(path.read_text("utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict):
            yield n, r
