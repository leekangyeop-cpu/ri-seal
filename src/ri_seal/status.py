"""`ri-seal status` — three pillars on one screen: security · efficiency · accuracy.

Every number is a count over local files in .riseal/ — nothing is judged here and nothing is sent anywhere.
`--details` lists, for each number, the file and line numbers it was counted from, so anyone can recount by hand.
"""
from __future__ import annotations

import html
import os
from collections import Counter
from datetime import datetime

from .claims import numbered, summarize
from .core import EDIT_TOOLS, STATE_DIR, Project, read_rows_checked

SMALL_N = 30

FOOTER = {
    "ko": "이 표시는 기록의 상태를 보여 주며 내용의 옳고 그름이나 성과를 보증하지 않습니다.",
    "en": "This display shows the state of the records. It does not vouch for whether their content is right, "
          "or for any result.",
}

COLOR_LABEL = {
    "ko": {"green": "이상 없음", "amber": "미완료", "red": "확인 필요"},
    "en": {"green": "nothing flagged", "amber": "incomplete", "red": "look at this"},
}


def default_lang() -> str:
    return "ko" if os.environ.get("LANG", "").lower().startswith("ko") else "en"


def _day(ts, tz) -> object:
    try:
        return datetime.fromisoformat(ts).astimezone(tz).date()
    except (TypeError, ValueError):
        return None


def compute(proj: Project, now: datetime | None = None) -> dict:
    now = now or datetime.now().astimezone()
    tz, today = now.tzinfo, now.date()
    ev: dict[str, dict] = {}
    rel = lambda p: f"{STATE_DIR}/{p.name}"                       # noqa: E731

    # ── security ──
    rec = list(numbered(proj.receipts))
    _, bad_r = read_rows_checked(proj.receipts)
    rec_today = [(n, r) for n, r in rec if _day(r.get("ts"), tz) == today]
    hidden = [n for n, r in rec_today for it in (r.get("event") or {}).get("paths") or []
              if it.get("path") in ("<redacted>", "<outside-project>")]
    seal_rows = list(numbered(proj.seals))
    seals = [(n, r) for n, r in seal_rows if r.get("kind") == "seal"]
    anchors = [(n, r) for n, r in seal_rows if r.get("kind") == "anchor"]
    seals_today = [n for n, r in seals if _day(r.get("sealed_at"), tz) == today]
    last_seal = seals[-1][1].get("sealed_at") if seals else None
    if not seals or not anchors:
        anchor_state = "none"
    else:
        methods: dict[str, set] = {}
        for _, a in anchors:
            methods.setdefault(a.get("target"), set()).add(a.get("method"))
        missing = [n for n, s in seals if not {"opentimestamps", "rfc3161"} <= methods.get(s.get("hash"), set())]
        anchor_state = "pending" if missing else "complete"
        ev["anchor_missing"] = {"file": rel(proj.seals), "lines": missing}
    vlog = list(numbered(proj.verify_log))
    last_verify = None
    if vlog:
        n, v = vlog[-1]
        last_verify = {"at": v.get("ts"), "ok": bool(v.get("ok")), "n_problems": v.get("n_problems", 0),
                       "n_changed": v.get("n_changed", 0)}
        ev["last_verify"] = {"file": rel(proj.verify_log), "lines": [n]}
    errs = proj.dir / "hook_errors.log"
    hook_errors = len(errs.read_text("utf-8", errors="replace").splitlines()) if errs.exists() else 0
    ev["receipts_today"] = {"file": rel(proj.receipts), "lines": [n for n, _ in rec_today]}
    ev["hidden_names_today"] = {"file": rel(proj.receipts), "lines": sorted(set(hidden))}
    ev["seals"] = {"file": rel(proj.seals), "lines": [n for n, _ in seals]}
    ev["anchors"] = {"file": rel(proj.seals), "lines": [n for n, _ in anchors]}
    if bad_r:
        ev["corrupted_receipt_lines"] = {"file": rel(proj.receipts), "lines": bad_r}
    security = {"receipts_today": len(rec_today), "hidden_names_today": len(hidden), "seals": len(seals),
                "seals_today": len(seals_today), "last_seal_at": last_seal, "anchor_state": anchor_state,
                "anchors": len(anchors), "last_verify": last_verify, "hook_errors": hook_errors,
                "corrupted_receipt_lines": len(bad_r)}

    # ── efficiency ──
    edits: Counter = Counter()
    edit_lines: dict[str, list[int]] = {}
    sessions: set = set()
    for n, r in rec_today:
        e = r.get("event") or {}
        if e.get("session_hmac"):
            sessions.add(e["session_hmac"])
        if e.get("tool") not in EDIT_TOOLS:
            continue
        for it in e.get("paths") or []:
            k = it.get("path") if it.get("path") not in ("<redacted>", "<outside-project>") else it.get("path_hmac")
            if k:
                edits[k] += 1
                edit_lines.setdefault(k, []).append(n)
    rework = [k for k, c in edits.items() if c >= 3]
    ev["files_edited_today"] = {"file": rel(proj.receipts), "lines": sorted({n for v in edit_lines.values() for n in v})}
    ev["rework_files_today"] = {"file": rel(proj.receipts), "lines": sorted({n for k in rework for n in edit_lines[k]})}
    ev["sessions_today"] = {"file": rel(proj.receipts), "lines": [n for n, r in rec_today
                                                                    if (r.get("event") or {}).get("session_hmac")]}
    efficiency = {"files_edited_today": len(edits), "edit_calls_today": sum(edits.values()),
                  "rework_files_today": len(rework), "sessions_today": len(sessions)}

    # ── accuracy ──
    acc = summarize(proj, 30, now)
    for k, lines in acc.pop("_lines").items():
        ev[f"claims_{k}"] = {"file": rel(proj.claims), "lines": lines}
    ev["claims_today"] = {"file": rel(proj.claims), "lines": acc.pop("_lines_today")}
    acc["small_n"] = acc["denominator"] < SMALL_N

    colors = {
        "security": "red" if (last_verify and not last_verify["ok"]) or bad_r else
                    ("amber" if anchor_state != "complete" or last_verify is None or hook_errors else "green"),
        "efficiency": "amber" if rework else "green",
        "accuracy": "red" if acc["unsupported_today"] else ("amber" if acc["small_n"] else "green"),
    }
    return {"date": today.isoformat(), "generated_at": now.isoformat(timespec="seconds"), "security": security,
            "efficiency": efficiency, "accuracy": acc, "colors": colors, "evidence": ev,
            "keyid": proj.cfg().get("keyid"), "privacy": proj.cfg().get("privacy"),
            "initialised": proj.config.exists()}


# ── wording ──────────────────────────────────────────────────────────

def _t(ts: str | None) -> str:
    if not ts:
        return "-"
    try:
        return datetime.fromisoformat(ts).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return ts


ANCHOR_WORD = {"ko": {"none": "없음", "pending": "대기", "complete": "영수증 받음"},
               "en": {"none": "none", "pending": "pending", "complete": "receipts received"}}


def _verify_word(v, lang):
    if v is None:
        return "아직 실행 안 함" if lang == "ko" else "not run yet"
    if lang == "ko":
        return f"{'문제 없음' if v['ok'] else '문제 ' + str(v['n_problems']) + '건'} ({_t(v['at'])})"
    return f"{'no problems' if v['ok'] else str(v['n_problems']) + ' problem(s)'} ({_t(v['at'])})"


def _rate(a) -> str:
    return "-" if a["hit_rate"] is None else f"{a['hit_rate'] * 100:.0f}%"


def sentences(d: dict, lang: str) -> dict:
    s, e, a = d["security"], d["efficiency"], d["accuracy"]
    aw = ANCHOR_WORD[lang][s["anchor_state"]]
    if lang == "ko":
        sec = (f"오늘 에이전트 행동 {s['receipts_today']}건이 영수증으로 남았고(이름 숨김 {s['hidden_names_today']}건), "
               f"봉인은 모두 {s['seals']}개(마지막 {_t(s['last_seal_at'])}), 외부 시각 고정은 '{aw}', "
               f"마지막 verify 는 {_verify_word(s['last_verify'], lang)}입니다.")
        eff = (f"오늘 세션 {e['sessions_today']}개에서 파일 {e['files_edited_today']}개를 편집했고, "
               f"같은 파일을 3번 이상 고친 경우는 {e['rework_files_today']}개입니다.")
        if a["denominator"] == 0:
            acc = f"최근 {a['window_days']}일 동안 영수증과 대조할 수 있었던 주장이 아직 없습니다(판단 보류 {a['unknown']}건)."
        else:
            acc = (f"최근 {a['window_days']}일 '했다'는 주장 {a['denominator']}건 중 영수증 흔적과 맞은 것은 "
                   f"{a['supported']}건({_rate(a)})이고 판단 보류 {a['unknown']}건은 따로 셉니다"
                   + (f" — 분모가 {SMALL_N}건 미만이라 비율을 믿기 이릅니다." if a["small_n"] else "."))
    else:
        sec = (f"Today {s['receipts_today']} agent action(s) were recorded as receipts ({s['hidden_names_today']} with "
               f"hidden names); {s['seals']} seal(s) in total (last {_t(s['last_seal_at'])}), external time anchors: {aw}, "
               f"last verify: {_verify_word(s['last_verify'], lang)}.")
        eff = (f"Today {e['files_edited_today']} file(s) were edited across {e['sessions_today']} session(s); "
               f"{e['rework_files_today']} of them were edited 3 or more times.")
        if a["denominator"] == 0:
            acc = (f"No claim in the last {a['window_days']} days could be checked against receipts yet "
                   f"({a['unknown']} left undecided).")
        else:
            acc = (f"Of {a['denominator']} 'done' claims in the last {a['window_days']} days, {a['supported']} "
                   f"({_rate(a)}) matched a trace in the receipts; {a['unknown']} undecided are counted separately"
                   + (f" — fewer than {SMALL_N}, too few to trust the rate." if a["small_n"] else "."))
    return {"security": sec, "efficiency": eff, "accuracy": acc}


def _rows(d: dict, lang: str) -> dict[str, list[tuple[str, str, str]]]:
    """pillar → [(label, value, evidence key)]."""
    s, e, a = d["security"], d["efficiency"], d["accuracy"]
    ko = lang == "ko"
    return {
        "security": [
            ("오늘 영수증" if ko else "receipts today", str(s["receipts_today"]), "receipts_today"),
            ("이름 숨김(HMAC)" if ko else "hidden names (HMAC)", str(s["hidden_names_today"]), "hidden_names_today"),
            ("봉인 수" if ko else "seals", f"{s['seals']} ({'오늘' if ko else 'today'} {s['seals_today']})", "seals"),
            ("마지막 봉인" if ko else "last seal", _t(s["last_seal_at"]), "seals"),
            ("시각 고정" if ko else "time anchors", f"{s['anchor_state']} ({s['anchors']})", "anchors"),
            ("마지막 verify" if ko else "last verify", _verify_word(s["last_verify"], lang), "last_verify"),
            ("훅 오류" if ko else "hook errors", str(s["hook_errors"]), ""),
        ],
        "efficiency": [
            ("오늘 편집 파일" if ko else "files edited today", str(e["files_edited_today"]), "files_edited_today"),
            ("편집 호출" if ko else "edit calls", str(e["edit_calls_today"]), "files_edited_today"),
            ("3회 이상 수정(재작업)" if ko else "edited 3+ times (rework)", str(e["rework_files_today"]), "rework_files_today"),
            ("세션 수" if ko else "sessions", str(e["sessions_today"]), "sessions_today"),
        ],
        "accuracy": [
            ("주장 적중률(30일)" if ko else "claim hit rate (30d)",
             _rate(a) + (f" · small_n (n={a['denominator']})" if a["small_n"] else f" (n={a['denominator']})"), ""),
            ("근거 있음(supported)" if ko else "supported", str(a["supported"]), "claims_supported"),
            ("근거 없음(unsupported)" if ko else "unsupported", str(a["unsupported"]), "claims_unsupported"),
            ("판단 보류(unknown)" if ko else "unknown", str(a["unknown"]), "claims_unknown"),
            ("부정·유보 문장" if ko else "negative/pending clauses", str(a["negative"]), "claims_negative"),
            ("오늘 주장" if ko else "claims today", str(a["claims_today"]), "claims_today"),
        ],
    }


TITLES = {"ko": {"security": "보안", "efficiency": "효율", "accuracy": "정확성"},
          "en": {"security": "Security", "efficiency": "Efficiency", "accuracy": "Accuracy"}}


def lines_spec(lines: list[int], limit: int = 40) -> str:
    if not lines:
        return "-"
    lines = sorted(set(lines))
    parts, start, prev = [], lines[0], lines[0]
    for x in lines[1:] + [None]:
        if x is not None and x == prev + 1:
            prev = x
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        if x is not None:
            start = prev = x
    more = f" … (+{len(parts) - limit})" if len(parts) > limit else ""
    return ",".join(parts[:limit]) + more


def render_text(d: dict, lang: str = "ko", details: bool = False, color: bool = False) -> str:
    sent = sentences(d, lang)
    T = TITLES[lang]
    ansi = {"green": "\033[32m", "amber": "\033[33m", "red": "\033[31m"}
    out = [("ri-seal 상태" if lang == "ko" else "ri-seal status") + f" — {d['date']}", ""]
    if not d["initialised"]:
        out.append("이 폴더는 아직 초기화되지 않았습니다: ri-seal init" if lang == "ko"
                   else "This folder is not initialised yet: ri-seal init")
        out.append("")
    for k in ("security", "efficiency", "accuracy"):
        out.append(f"  {T[k]}: {sent[k]}")
    out.append("")
    for k, rows in _rows(d, lang).items():
        c = d["colors"][k]
        tag = f"[{COLOR_LABEL[lang][c]}]"
        if color:
            tag = f"{ansi[c]}{tag}\033[0m"
        out.append(f"■ {T[k]} {tag}")
        w = max(len(r[0]) for r in rows) + 2
        for label, val, key in rows:
            line = f"    {label.ljust(w)}{val}"
            if details and key and key in d["evidence"]:
                e = d["evidence"][key]
                line += f"    ← {e['file']}:{lines_spec(e['lines'])}"
            out.append(line)
        out.append("")
    if details:
        out.append("근거: 파일:줄번호(1부터, 물리적 줄). 직접 열어 다시 셀 수 있습니다." if lang == "ko"
                   else "Evidence: file:line numbers (1-based physical lines). Open the file and recount.")
        out.append("")
    out.append(FOOTER[lang])
    return "\n".join(out)


# ── local HTML page (used by `ri-seal ui`) ───────────────────────────

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e2dc;
--green:#2f7d4f;--amber:#a86b00;--red:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--fg:#ecece8;--muted:#a3a39c;--line:#33332f;
--green:#6cc08b;--amber:#e0a740;--red:#f08078}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Segoe UI",sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 40px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);font-size:13px;margin-bottom:18px}
.sum{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:18px}
.sum p{margin:6px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--c);border-radius:10px;padding:14px 16px}
.card h2{font-size:16px;margin:0 0 2px;display:flex;justify-content:space-between;gap:8px}
.tag{font-size:12px;color:var(--c);font-weight:600}
table{width:100%;border-collapse:collapse;font-size:14px}td{padding:5px 0;border-top:1px solid var(--line);vertical-align:top}
td.v{text-align:right;font-variant-numeric:tabular-nums;font-weight:600}
.ev{display:block;color:var(--muted);font-size:11px;font-weight:400;word-break:break-all}
footer{margin-top:22px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}
.green{--c:var(--green)}.amber{--c:var(--amber)}.red{--c:var(--red)}
"""


def render_html(d: dict, lang: str = "ko") -> str:
    esc = html.escape
    sent = sentences(d, lang)
    T = TITLES[lang]
    cards = []
    for k, rows in _rows(d, lang).items():
        c = d["colors"][k]
        trs = []
        for label, val, key in rows:
            evs = ""
            if key and key in d["evidence"]:
                e = d["evidence"][key]
                evs = f'<span class="ev">{esc(e["file"])}:{esc(lines_spec(e["lines"], 12))}</span>'
            trs.append(f"<tr><td>{esc(label)}</td><td class=\"v\">{esc(val)}{evs}</td></tr>")
        cards.append(f'<section class="card {c}"><h2>{esc(T[k])}<span class="tag">{esc(COLOR_LABEL[lang][c])}</span></h2>'
                     f'<table>{"".join(trs)}</table></section>')
    summ = "".join(f"<p><b>{esc(T[k])}</b> · {esc(sent[k])}</p>" for k in ("security", "efficiency", "accuracy"))
    title = "ri-seal 상태" if lang == "ko" else "ri-seal status"
    sub = (f"{d['date']} · 읽기 전용 · 이 컴퓨터(127.0.0.1)에서만 열림 · 새로 고치면 다시 셉니다" if lang == "ko"
           else f"{d['date']} · read-only · served on 127.0.0.1 only · reload to recount")
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
            f"<style>{CSS}</style></head><body><main><h1>{esc(title)}</h1><div class=\"sub\">{esc(sub)}</div>"
            f'<div class="sum">{summ}</div><div class="grid">{"".join(cards)}</div>'
            f"<footer>{esc(FOOTER[lang])}</footer></main></body></html>")
