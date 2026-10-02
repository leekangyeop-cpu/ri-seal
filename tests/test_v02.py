"""0.2 tests: strict default, three-pillar status, claim ↔ receipt self-check, hook fail-open, install/uninstall, local UI.
No network: the UI test talks to 127.0.0.1 only; `anchor` is never called."""
import io
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from ri_seal import cli
from ri_seal.claims import extract, last_assistant_text, record
from ri_seal.core import Project, append, init, keyed, pepper, read_rows, receipt_from_hook, seal
from ri_seal.status import FOOTER, compute, lines_spec, render_html, render_text

REPO = Path(__file__).resolve().parents[1]


def _mk(tmp_path, monkeypatch, privacy=None):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    root = tmp_path / "work"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "a.py").write_text("print(1)\n")
    (root / "src" / "b.py").write_text("print(2)\n")
    (root / "tests" / "test_a.py").write_text("def test(): pass\n")
    p = Project(root)
    kw = {} if privacy is None else {"privacy": privacy}
    init(p, key_dir=tmp_path / "home" / ".riseal" / "keys", **kw)
    return p


@pytest.fixture
def sp(tmp_path, monkeypatch):            # strict (the 0.2 default)
    return _mk(tmp_path, monkeypatch)


@pytest.fixture
def np_(tmp_path, monkeypatch):           # normal
    return _mk(tmp_path, monkeypatch, "normal")


def edit(p, f, sid="S1", agent=None):
    ev = {"tool_name": "Edit", "tool_input": {"file_path": str(p.root / f)}, "session_id": sid}
    if agent:
        ev["agent_id"] = agent
    receipt_from_hook(p, ev)


def bash(p, cmd, out="", sid="S1"):
    receipt_from_hook(p, {"tool_name": "Bash", "tool_input": {"command": cmd}, "tool_response": {"stdout": out, "stderr": ""},
                          "session_id": sid})


# ── 5. strict default ────────────────────────────────────────────────

def test_strict_is_default_in_core_and_cli(sp, tmp_path, monkeypatch, capsys):
    assert sp.cfg()["privacy"] == "strict"
    edit(sp, "src/a.py")
    assert "a.py" not in sp.receipts.read_text()
    monkeypatch.setenv("HOME", str(tmp_path / "h2"))
    root = tmp_path / "cli_proj"
    root.mkdir()
    assert cli.main(["--dir", str(root), "init"]) == 0
    assert json.loads((root / ".riseal" / "config.json").read_text())["privacy"] == "strict"
    root2 = tmp_path / "cli_proj2"
    root2.mkdir()
    assert cli.main(["--dir", str(root2), "init", "--privacy", "normal"]) == 0
    assert json.loads((root2 / ".riseal" / "config.json").read_text())["privacy"] == "standard"
    with pytest.raises(ValueError):
        init(Project(tmp_path / "x"), privacy="loose")


# ── receipts: test-run class and counts, never the command ───────────

def test_test_run_class_and_counts_only(np_):
    bash(np_, ".venv/bin/python -m pytest -q tests/test_a.py", "....\n4 passed, 1 failed in 0.2s\n")
    bash(np_, "grep pytest README.md", "pytest\n")
    rows = read_rows(np_.receipts)
    assert rows[0]["event"]["cmd_class"] == "test" and rows[0]["event"]["test_counts"] == {"passed": 4, "failed": 1, "errors": 0}
    assert "cmd_class" not in rows[1]["event"]                       # grep mentioning pytest is not a test run
    raw = np_.receipts.read_text()
    assert "tests/test_a.py" not in raw and "-m pytest" not in raw


# ── 2. claim extraction ──────────────────────────────────────────────

def test_extract_kinds_negatives_and_code_blocks():
    text = ("- tests/test_a.py 42 passed, 0 failed\n- src/a.py 수리했습니다\n- 라이브는 아직 검증하지 못했습니다\n"
            "```\n99 passed\n```\nAll done. Implemented src/b.py; UI not verified yet.\n테스트 65개 통과")
    c = extract(text)
    kinds = [(x["kind"], x["n_passed"]) for x in c]
    assert ("test", 42) in kinds and ("test", 65) in kinds and ("test", 99) not in kinds
    assert ("fix", None) in kinds and ("build", None) in kinds and ("complete", None) in kinds
    assert sum(k == "negative" for k, _ in kinds) == 2
    assert next(x for x in c if x["kind"] == "fix")["files"] == ["src/a.py"]
    assert extract("0 failed") == []                                  # a zero-failure count is not a claim, nor negative


def test_last_assistant_text_from_transcript(tmp_path):
    tp = tmp_path / "t.jsonl"
    lines = [
        {"type": "user", "message": {"role": "user", "content": "do it"}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "old reply"}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "content": "x"}]}},
        {"type": "assistant", "isSidechain": True, "message": {"content": [{"type": "text", "text": "sub-agent text"}]}},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Edit"}]}},
        {"type": "assistant", "message": {"content": [{"type": "text", "text": "final: 3 passed"}]}},
    ]
    tp.write_text("\n".join(json.dumps(x) for x in lines) + "\nnot json\n")
    assert last_assistant_text({"transcript_path": str(tp)}) == "final: 3 passed"
    assert last_assistant_text({"last_assistant_message": "direct", "transcript_path": str(tp)}) == "direct"
    assert last_assistant_text({"transcript_path": str(tmp_path / "missing")}) == ""


# ── 2. judging against receipts ──────────────────────────────────────

def _status_of(rows, kind):
    return [r["status"] for r in rows if r["kind"] == kind]


def test_claims_judged_against_same_session(np_):
    edit(np_, "src/a.py")
    bash(np_, "pytest -q", "12 passed in 0.1s")
    edit(np_, "src/b.py", sid="OTHER")                                # another session's work is not evidence
    rows = record(np_, "Fixed src/a.py. Fixed src/b.py. 12 passed. 13 passed. Verified README.md. "
                       "Nothing to verify later.", "S1")
    by = {(r.get("claim") or "")[:16]: r["status"] for r in rows}
    assert by["Fixed src/a.py."] == "supported"
    assert by["Fixed src/b.py."] == "unsupported"
    assert by["12 passed."] == "supported"
    assert by["13 passed."] == "unsupported"                          # count not seen in any run of this session
    assert by["Verified README."] == "unsupported"
    assert all(r["session_hmac"] for r in rows) and "S1" not in np_.claims.read_text()
    assert record(np_, "Fixed src/a.py. Fixed src/b.py. 12 passed. 13 passed. Verified README.md. "
                       "Nothing to verify later.", "S1") == []        # the same message is recorded once


def test_test_claim_without_run_is_unsupported_and_failures_unknown(np_):
    edit(np_, "src/a.py")
    assert record(np_, "All tests passed.", "S1")[0]["status"] == "unsupported"
    bash(np_, "pytest -x", "(no summary line)", sid="S2")
    assert record(np_, "4 passed.", "S2")[0]["evidence"]["reason"] == "test_run_without_summary"
    bash(np_, "python -m pytest", "3 passed, 2 failed in 1s")
    assert record(np_, "5 tests passed.", "S1")[0]["status"] == "unknown"


def test_command_class_head_only_and_count_parsing():
    from ri_seal.core import command_class, summary_counts
    for cmd in ("pytest -q", "cd x && .venv/bin/python -m pytest tests", "FOO=1 uv run pytest", "npm test",
                "npm run test", "go test ./...", "python3.12 -m unittest", "make test"):
        assert command_class(cmd) == "test", cmd
    for cmd in ("grep pytest README.md", "echo 'pytest'", "pip install pytest", "cat test.py", "npm install"):
        assert command_class(cmd) is None, cmd
    assert summary_counts({"stdout": "x\n12 passed, 1 failed, 2 errors in 3s\n"}) == {"passed": 12, "failed": 1, "errors": 2}
    assert summary_counts("....\\n2 passed in 0.1s") == {"passed": 2, "failed": 0, "errors": 0}
    assert summary_counts({"stdout": "nothing"}) is None


def test_bare_file_name_matches_project_file_in_strict(sp):
    edit(sp, "src/a.py")
    (sp.root / "node_modules" / "x").mkdir(parents=True)
    (sp.root / "node_modules" / "x" / "b.py").write_text("")             # vendor folders are not indexed
    rows = record(sp, "Fixed a.py. Fixed b.py.", "S1")
    assert [r["status"] for r in rows] == ["supported", "unsupported"]


def test_test_command_without_summary_is_unknown_not_supported(np_):
    bash(np_, "pytest --version", "pytest 9.1.1")
    bash(np_, "pytest --collect-only -q", "tests/test_a.py::test\n")
    rows = record(np_, "All tests passed. Verified everything.", "S1")
    assert [(r["kind"], r["status"], r["evidence"]["reason"]) for r in rows] == [
        ("test", "unknown", "test_run_without_summary"), ("verify", "unknown", "test_run_without_summary")]


def test_truncated_index_makes_unfound_bare_name_unknown(np_):
    from ri_seal.claims import NameIndex, basename_index, judge
    edit(np_, "src/a.py")
    idx = basename_index(np_.root, limit=1)
    assert idx.truncated is True
    rows = [r for r in read_rows(np_.receipts)]
    claim = {"clause": "Fixed zzz.py", "kind": "fix", "files": ["zzz.py"], "n_passed": None}
    st, ev = judge(np_, pepper(np_), rows, claim, idx)
    assert st == "unknown" and ev["reason"] == "index_incomplete_name_not_found" and ev["index_truncated"]
    st2, _ = judge(np_, pepper(np_), rows, claim, NameIndex())          # complete index → really not touched
    assert st2 == "unsupported"
    assert basename_index(np_.root).truncated is False


def test_is_ours_exact_shapes_only():
    for cmd, sub in (("ri-seal hook", "hook"), ('"/u/.venv/bin/ri-seal" hook', "hook"),
                     ('"/usr/bin/python3" -m ri_seal claim-hook', "claim-hook")):
        assert cli.is_ours(cmd, sub), cmd
    for cmd, sub in (("not-ri-seal hook", "hook"), ("/opt/ri-seal hook", "hook"), ("echo x; ri-seal hook", "hook"),
                     ('"/x/not-ri-seal" hook', "hook"), ("ri-seal hook", "claim-hook"), ("python -m ri_seal hook", "hook")):
        assert not cli.is_ours(cmd, sub), cmd


def test_hook_errors_log_is_private(np_, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
    cli.cmd_hook(np_)
    log = np_.dir / "hook_errors.log"
    assert log.stat().st_mode & 0o777 == 0o600
    log.chmod(0o644)                                                   # a log left 0644 by 0.1 is tightened
    monkeypatch.setattr(sys, "stdin", io.StringIO("[]"))
    cli.cmd_claim_hook(np_)
    assert log.stat().st_mode & 0o777 == 0o600 and len(log.read_text().splitlines()) == 2


def test_mixed_agents_make_claims_unknown(np_):
    edit(np_, "src/a.py")
    edit(np_, "src/b.py", agent="sub-1")
    r = record(np_, "Fixed src/a.py.", "S1")[0]
    assert r["status"] == "unknown" and r["evidence"]["mixed_agents"] is True


def test_no_session_receipts_is_unknown(np_):
    assert record(np_, "Fixed src/a.py.", "S-none")[0]["status"] == "unknown"


def test_strict_claims_store_hmac_not_text(sp):
    edit(sp, "src/a.py")
    rows = record(sp, "Fixed src/a.py.", "S1")
    raw = sp.claims.read_text()
    assert rows[0]["status"] == "supported"                           # strict receipts still matched through the HMAC
    assert "src/a.py" not in raw and "Fixed" not in raw
    assert rows[0]["claim_hmac"] == keyed(pepper(sp), "claim:Fixed src/a.py.") and rows[0]["n_files"] == 1


def test_sensitive_path_in_claim_is_hmac_in_normal_mode(np_):
    rows = record(np_, "Fixed config/api_token.json.", "S1")
    assert "claim" not in rows[0] and "api_token" not in np_.claims.read_text()


def test_claims_file_is_hash_chained(np_):
    edit(np_, "src/a.py")
    record(np_, "Fixed src/a.py. Done src/b.py.", "S1")
    rows = read_rows(np_.claims)
    assert [r["seq"] for r in rows] == [0, 1] and rows[1]["prev"] == rows[0]["hash"]


# ── 2. the Stop hook is fail-open ────────────────────────────────────

@pytest.mark.parametrize("stdin", ["not json", "[1,2]", '{"transcript_path": 5}', "", '{"session_id": "S1", "transcript_path": "/nonexistent"}'])
def test_claim_hook_never_fails(np_, monkeypatch, capsys, stdin):
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    assert cli.cmd_claim_hook(np_) == 0
    out = capsys.readouterr()
    assert out.out == "" and len(out.err.splitlines()) <= 1


def test_claim_hook_records_from_stop_payload(np_, monkeypatch, capsys, tmp_path):
    edit(np_, "src/a.py")
    tp = tmp_path / "tr.jsonl"
    tp.write_text(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "Fixed src/a.py."}]}}) + "\n")
    payload = {"session_id": "S1", "transcript_path": str(tp), "cwd": str(np_.root), "hook_event_name": "Stop"}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    assert cli.cmd_claim_hook(Project(np_.root / "src")) == 0          # found by walking up from a sub-folder
    assert capsys.readouterr().out == ""
    assert read_rows(np_.claims)[0]["status"] == "supported"


def test_claim_hook_error_goes_to_stderr_one_line(np_, monkeypatch, capsys):
    import ri_seal.claims as cl
    monkeypatch.setattr(cl, "record", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"last_assistant_message": "Done src/a.py", "session_id": "S"})))
    assert cli.cmd_claim_hook(np_) == 0
    out = capsys.readouterr()
    assert out.out == "" and out.err.count("\n") == 1 and "OSError" in out.err
    assert "claim-hook OSError" in (np_.dir / "hook_errors.log").read_text()


# ── 1. status ────────────────────────────────────────────────────────

def test_status_counts_on_synthetic_receipts(sp):
    for _ in range(3):
        edit(sp, "src/a.py")                                          # rework: same file 3 times
    edit(sp, "src/b.py", sid="S2")
    bash(sp, "pytest -q", "7 passed in 0.1s")
    receipt_from_hook(sp, {"tool_name": "Read", "tool_input": {"file_path": str(sp.root / "src/a.py")}, "session_id": "S1"})
    seal(sp)
    record(sp, "Fixed src/a.py. Fixed src/b.py. 7 passed. Not verified yet.", "S1")
    d = compute(sp)
    s, e, a = d["security"], d["efficiency"], d["accuracy"]
    assert s["receipts_today"] == 6 and s["hidden_names_today"] == 5 and s["seals"] == 1 and s["anchor_state"] == "none"
    assert s["last_verify"] is None and s["last_seal_at"]
    assert e == {"files_edited_today": 2, "edit_calls_today": 4, "rework_files_today": 1, "sessions_today": 2}
    # S1: a.py edited (supported); b.py edited only in S2 (unsupported); 7 passed (supported); negative clause excluded
    assert (a["supported"], a["unsupported"], a["negative"], a["denominator"]) == (2, 1, 1, 3)
    assert a["hit_rate"] == pytest.approx(2 / 3) and a["small_n"] is True
    assert d["colors"]["efficiency"] == "amber" and d["colors"]["accuracy"] == "red" and d["colors"]["security"] == "amber"
    assert d["evidence"]["rework_files_today"]["lines"] == [1, 2, 3]
    assert d["evidence"]["claims_unsupported"]["file"] == ".riseal/claims.jsonl"


def test_status_only_counts_today(np_):
    edit(np_, "src/a.py")
    tomorrow = datetime.now().astimezone() + timedelta(days=1)
    d = compute(np_, now=tomorrow)
    assert d["security"]["receipts_today"] == 0 and d["efficiency"]["files_edited_today"] == 0


def test_status_anchor_states_and_last_verify(np_, capsys):
    seal(np_)
    h = [r for r in read_rows(np_.seals) if r["kind"] == "seal"][0]["hash"]
    append(np_.seals, lambda prev, seq: {"seq": seq, "prev": prev, "kind": "anchor", "target": h, "method": "opentimestamps",
                                         "receipt": "", "detail": {}})
    assert compute(np_)["security"]["anchor_state"] == "pending"
    append(np_.seals, lambda prev, seq: {"seq": seq, "prev": prev, "kind": "anchor", "target": h, "method": "rfc3161",
                                         "receipt": "", "detail": {}})
    assert compute(np_)["security"]["anchor_state"] == "complete"
    cli.main(["--dir", str(np_.root), "verify"])                     # fake anchors → verify finds problems, and that is kept
    lv = compute(np_)["security"]["last_verify"]
    assert lv["ok"] is False and lv["n_problems"] >= 1
    assert compute(np_)["colors"]["security"] == "red"


def test_status_text_has_summary_details_and_footer(sp, capsys):
    edit(sp, "src/a.py")
    for lang in ("ko", "en"):
        t = render_text(compute(sp), lang, details=True)
        assert t.rstrip().endswith(FOOTER[lang])
        assert ".riseal/receipts.jsonl:1" in t
        head = t.split("\n\n")[1].splitlines()                         # three summary sentences right under the title
        assert len(head) == 3
    assert "이 표시는 기록의 상태를 보여 주며 내용의 옳고 그름이나 성과를 보증하지 않습니다" in FOOTER["ko"]
    assert cli.main(["--dir", str(sp.root), "status", "--lang", "en"]) == 0
    assert "Security" in capsys.readouterr().out
    assert cli.main(["--dir", str(sp.root), "status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["security"]["receipts_today"] == 1


def test_status_on_uninitialised_folder(tmp_path):
    t = render_text(compute(Project(tmp_path)), "ko")
    assert "ri-seal init" in t


def test_lines_spec():
    assert lines_spec([1, 2, 3, 5, 7, 8]) == "1-3,5,7-8" and lines_spec([]) == "-"


def test_html_page_is_self_contained(sp):
    record(sp, "Fixed src/a.py.", "S1")
    page = render_html(compute(sp), "ko")
    assert "<script" not in page.lower() and not re.search(r"(?:src|href)=[\"']?(?:https?:)?//", page)
    assert "@import" not in page and "url(" not in page
    assert FOOTER["ko"] in page and "src/a.py" not in page and "Fixed" not in page


# ── 3. local UI ──────────────────────────────────────────────────────

def test_ui_binds_loopback_only_and_is_read_only(np_):
    import threading
    from ri_seal import ui
    srv = ui.make_server(np_, port=0, lang="en")
    try:
        assert srv.server_address[0] == "127.0.0.1"
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never route loopback through a proxy
        r = opener.open(base + "/", timeout=5)
        body = r.read().decode()
        assert r.status == 200 and FOOTER["en"] in body and "default-src 'none'" in r.headers["Content-Security-Policy"]
        for path, method, code in (("/x", "GET", 404), ("/", "POST", 405)):
            with pytest.raises(urllib.error.HTTPError) as e:
                opener.open(urllib.request.Request(base + path, method=method, data=b"" if method == "POST" else None), timeout=5)
            assert e.value.code == code
        with pytest.raises(urllib.error.HTTPError) as e:                # DNS-rebinding style Host header
            opener.open(urllib.request.Request(base + "/", headers={"Host": "evil.example:80"}), timeout=5)
        assert e.value.code == 421
        for host in ("127.0.0.1", "localhost"):                          # port-less loopback Host is accepted
            assert opener.open(urllib.request.Request(base + "/", headers={"Host": host}), timeout=5).status == 200
        with pytest.raises(urllib.error.HTTPError) as e:
            opener.open(urllib.request.Request(base + "/", headers={"Host": "evil.example"}), timeout=5)
        assert e.value.code == 421
    finally:
        srv.shutdown()
        srv.server_close()
    import inspect
    assert "HOST = \"127.0.0.1\"" in inspect.getsource(ui) and "0.0.0.0" not in inspect.getsource(ui)


# ── 4. install / uninstall ───────────────────────────────────────────

OTHER_HOOKS = {
    "permissions": {"allow": ["Read"]},
    "hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-guard"}]}],
        "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt-on-save"}]}],
        "Stop": [{"hooks": [{"type": "command", "command": "notify-done"}]}],
    },
}


def test_install_adds_both_hooks_with_preview_and_opt_out(np_):
    s = np_.root / ".claude" / "settings.local.json"
    s.parent.mkdir()
    s.write_text(json.dumps(OTHER_HOOKS))
    dry = cli.cmd_install_claude_hook(np_, dry_run=True)
    assert not dry["installed"] and json.loads(s.read_text()) == OTHER_HOOKS and any(l.startswith("+") for l in dry["preview"])
    r = cli.cmd_install_claude_hook(np_)
    assert r["installed"] and r["added"] == ["PostToolUse", "Stop"] and r["preview"]
    d = json.loads(s.read_text())
    assert d["hooks"]["Stop"][1]["hooks"][0]["command"].endswith(" claim-hook")
    assert d["hooks"]["PostToolUse"][1]["hooks"][0]["command"].endswith(" hook")
    assert not cli.cmd_install_claude_hook(np_)["installed"]
    sh = cli.cmd_install_claude_hook(np_, local=False, claim_hook=False)
    shared = json.loads((np_.root / ".claude" / "settings.json").read_text())
    assert sh["added"] == ["PostToolUse"] and "Stop" not in shared["hooks"]


def test_uninstall_removes_exactly_ours(np_):
    s = np_.root / ".claude" / "settings.local.json"
    s.parent.mkdir()
    s.write_text(json.dumps(OTHER_HOOKS))
    cli.cmd_install_claude_hook(np_)
    d = json.loads(s.read_text())
    d["hooks"]["Stop"][0]["hooks"].append({"type": "command", "command": '"/x/bin/ri-seal" claim-hook'})   # ours, sharing a group
    s.write_text(json.dumps(d))
    dry = cli.cmd_uninstall_claude_hook(np_, dry_run=True)
    assert dry["removed"] == 0 and dry["removed_would_be"] == 3 and dry["preview"]
    r = cli.cmd_uninstall_claude_hook(np_)
    assert r["removed"] == 3
    assert json.loads(s.read_text()) == OTHER_HOOKS                     # every other hook back exactly as it was
    assert cli.cmd_uninstall_claude_hook(np_)["removed"] == 0


def test_uninstall_drops_hooks_key_it_emptied(np_):
    cli.cmd_install_claude_hook(np_)
    s = np_.root / ".claude" / "settings.local.json"
    assert cli.cmd_uninstall_claude_hook(np_)["removed"] == 2
    assert json.loads(s.read_text()) == {}


def test_uninstall_does_not_touch_lookalikes(np_):
    s = np_.root / ".claude" / "settings.local.json"
    s.parent.mkdir()
    keep = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "not-ri-seal claim-hook-x"}]}],
                      "PostToolUse": [{"hooks": [{"type": "command", "command": "echo ri-seal hook && other"}]}]}}
    s.write_text(json.dumps(keep))
    assert cli.cmd_uninstall_claude_hook(np_)["removed"] == 0 and json.loads(s.read_text()) == keep


def test_cli_install_prints_preview(np_, capsys):
    assert cli.main(["--dir", str(np_.root), "install-claude-hook", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "(after)" in out and "claim-hook" in out
    assert not (np_.root / ".claude" / "settings.local.json").exists()


# ── 6. documents: no overclaiming words ──────────────────────────────

def _lint():
    import importlib.util
    spec = importlib.util.spec_from_file_location("lint_wording", REPO / "scripts" / "lint_wording.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_public_docs_pass_wording_lint(capsys):
    lint = _lint()
    assert lint.main([]) == 0, capsys.readouterr().out                 # README·DISCLAIMER·PRIVACY·SECURITY, ko and en
    assert lint.main([str(REPO / "CHANGELOG.md"), str(REPO / "NOTICE")]) == 0


def test_wording_lint_allows_only_negative_sentences():
    lint = _lint()
    assert lint.check_text("ri-seal 은 공증 서비스가 아닙니다.") == []
    assert lint.check_text("It does not guarantee results.") == []
    assert [w for _, w, _ in lint.check_text("공증된 기록을 제공합니다.")] == ["공증"]
    assert [w for _, w, _ in lint.check_text("Guaranteed alpha for you.")] == ["guarantee", "alpha"]
    # a negation in one table cell does not excuse a word in the next cell
    assert [w for _, w, _ in lint.check_text("| 보여 주지 않는 것 | 법적 효력 있음 |")] == ["법적 효력"]
    assert lint.check_text("optional `certifi` package") == []           # package name, not a claim


def test_docs_exist():
    for name in ("CONTRIBUTING.md", "CONTRIBUTING.en.md", "CHANGELOG.md", "NOTICE"):
        assert (REPO / name).read_text("utf-8").strip()


def test_disclaimer_carries_spec_sentences():
    ko = (REPO / "DISCLAIMER.md").read_text("utf-8")
    en = (REPO / "DISCLAIMER.en.md").read_text("utf-8")
    assert "다만 고의 또는 중대한 과실로 인한 손해는 제외합니다" in ko
    assert "공인전자서명·공인 시점확인·공증·인증 서비스가 아니며 내용의 진위·성과·완전성·법적 효력을 보증하지 않습니다" in ko
    for t in (ko, en):
        assert "OpenTimestamps" in t and "FreeTSA" in t and "Ed25519" in t and "SHA-256" in t
    assert "대한민국 법" in ko and "Republic of Korea" in en and "gross negligence" in en
    assert "Apache License 2.0 (see Section 6)" in (REPO / "NOTICE").read_text("utf-8")


def test_contributing_requires_dco_and_tests():
    for name in ("CONTRIBUTING.md", "CONTRIBUTING.en.md"):
        t = (REPO / name).read_text("utf-8")
        assert "Signed-off-by" in t and "Apache License 2.0" in t and "pytest" in t and "lint_wording" in t


def test_security_has_disclosure_window_and_versions():
    for name in ("SECURITY.md", "SECURITY.en.md"):
        t = (REPO / name).read_text("utf-8")
        assert "90" in t and "0.2.x" in t and "contact@rootinsidegroup.com" in t


def test_readme_not_guaranteed_section_comes_before_install():
    ko = (REPO / "README.md").read_text("utf-8")
    en = (REPO / "README.en.md").read_text("utf-8")
    assert ko.index("## 이 도구가 보장하지 않는 것") < ko.index("## 3분 시작")
    assert en.index("## What this tool does not guarantee") < en.index("## Three-minute start")


def test_release_script_is_documented_not_run():
    t = (REPO / "scripts" / "release.sh").read_text("utf-8")
    for step in ("git tag", "python -m build", "SHA256SUMS", "ri-seal", "seal", "anchor", "export"):
        assert step in t
    assert "RISEAL_RELEASE_CONFIRM" in t
