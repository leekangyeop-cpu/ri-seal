import base64
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import pytest

from ri_seal import anchor, cli
from ri_seal.core import Project, init, read_rows, receipt_from_hook, seal, verify, pae


@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    root = tmp_path / "work"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("print(1)\n")
    p = Project(root)
    info = init(p, key_dir=tmp_path / "home" / ".riseal" / "keys")
    return p, info


def _hook(p, event):
    receipt_from_hook(p, event)


def test_init_key_outside_project_and_private(proj):
    p, info = proj
    kp = Path(info["key"])
    assert p.root not in kp.parents and kp.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        init(p)


def test_receipts_store_hashes_not_content(proj):
    p, _ = proj
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": str(p.root / "src/a.py"), "old_string": "SECRET"}, "session_id": "s1"})
    _hook(p, {"tool_name": "Bash", "tool_input": {"command": "export TOKEN=abc123"}})
    raw = p.receipts.read_text()
    assert "SECRET" not in raw and "abc123" not in raw
    rows = read_rows(p.receipts)
    assert rows[0]["event"]["paths"][0]["path"] == "src/a.py" and len(rows[0]["event"]["paths"][0]["sha256"]) == 64
    assert len(rows[1]["event"]["command_hmac"]) == 64 and rows[1]["prev"] == rows[0]["hash"]
    import hashlib
    assert hashlib.sha256(b"export TOKEN=abc123").hexdigest() not in raw      # short secret not guessable from a plain hash
    assert rows[0]["event"]["session_hmac"] != "s1"


def test_outside_project_path_is_masked(proj, tmp_path):
    p, _ = proj
    other = tmp_path / "elsewhere.txt"
    other.write_text("x")
    _hook(p, {"tool_name": "Read", "tool_input": {"file_path": str(other)}})
    item = read_rows(p.receipts)[0]["event"]["paths"][0]
    assert item["path"] == "<outside-project>" and str(tmp_path) not in json.dumps(item)


def test_seal_and_verify_ok(proj):
    p, _ = proj
    _hook(p, {"tool_name": "Write", "tool_input": {"file_path": "src/a.py"}})
    r = seal(p, [Path("src")], "first")
    st = json.loads(base64.b64decode(r["envelope"]["payload"]))
    assert st["_type"] == "https://in-toto.io/Statement/v1"
    assert {s["name"] for s in st["subject"]} == {".riseal/receipts.jsonl", "src/a.py"}
    v = verify(p)
    assert v["ok"] and v["n_seals"] == 1 and not v["files_changed_since_seal"]


def test_detects_receipt_rewrite_after_seal(proj):
    p, _ = proj
    for i in range(3):
        _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "src/a.py"}})
    seal(p)
    rows = read_rows(p.receipts)[:2]                       # agent deletes its last action
    p.receipts.write_text("".join(json.dumps(r) + "\n" for r in rows))
    v = verify(p)
    assert not v["ok"] and any("rewritten or removed" in x for x in v["problems"])


def test_detects_edited_receipt_row(proj):
    p, _ = proj
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "src/a.py"}})
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "src/a.py"}})
    rows = read_rows(p.receipts)
    rows[0]["event"]["tool"] = "Read"
    p.receipts.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert any("row edited" in x for x in verify(p)["problems"])


def test_file_change_after_seal_reported(proj):
    p, _ = proj
    seal(p, [Path("src/a.py")])
    (p.root / "src/a.py").write_text("print(2)\n")
    v = verify(p)
    assert v["ok"] and v["files_changed_since_seal"] == ["src/a.py: changed since seal 0"]


def test_tampered_signature_rejected(proj):
    p, _ = proj
    seal(p)
    rows = read_rows(p.seals)
    st = json.loads(base64.b64decode(rows[0]["envelope"]["payload"]))
    st["predicate"]["note"] = "forged"
    rows[0]["envelope"]["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
    from ri_seal.core import row_hash
    rows[0]["hash"] = row_hash(rows[0])
    p.seals.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert any("does not match" in x for x in verify(p)["problems"])


def test_hook_never_fails(proj, monkeypatch, capsys):
    p, _ = proj
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json"))
    assert cli.cmd_hook(p) == 0
    assert capsys.readouterr().out == ""


def test_install_claude_hook_idempotent_with_backup(proj):
    p, _ = proj
    s = p.root / ".claude" / "settings.json"
    s.parent.mkdir()
    s.write_text(json.dumps({"permissions": {"allow": ["Read"]}}))
    assert cli.cmd_install_claude_hook(p, local=False)["installed"]
    assert not cli.cmd_install_claude_hook(p, local=False)["installed"]
    d = json.loads(s.read_text())
    assert d["permissions"] == {"allow": ["Read"]} and s.with_suffix(".json.bak").exists()
    h = d["hooks"]["PostToolUse"][0]["hooks"][0]
    assert h["command"] == "ri-seal hook" and h["timeout"] == 10                                    # shared file: no machine path
    first_bak = s.with_suffix(".json.bak").read_text()
    cli.cmd_install_claude_hook(p, local=False)
    loc = cli.cmd_install_claude_hook(p)                                                             # default = local, absolute path
    lh = json.loads((p.root / ".claude" / "settings.local.json").read_text())["hooks"]["PostToolUse"][0]["hooks"][0]
    assert loc["installed"] and lh["command"].startswith('"') and lh["command"].endswith(" hook")
    assert s.with_suffix(".json.bak").read_text() == first_bak                                      # original backup kept


def test_anchor_offline_and_failure_isolation(proj):
    p, _ = proj
    seal(p)

    def fake_post(url, body, headers, timeout=30):
        if "b.pool" in url:
            raise OSError("down")
        if url.endswith("/digest"):
            assert len(body) == 32
            return b"\xf0\x01x"
        # a TSA token carries the messageImprint (our digest) and the nonce we sent — mimic that so the response check passes
        return anchor._der(0x30, anchor._der(0x30, anchor._der_int(0)) + anchor._der(0x30, b"tok" + body))

    res = anchor.anchor_pending(p, post=fake_post)
    assert [r["ok"] for r in res] == [True, False, True]
    assert anchor.pending(p) == [] and verify(p)["ok"] and verify(p)["n_anchors"] == 2
    assert any(x.suffix == ".ots" for x in p.proofs.iterdir())


def test_export_bundle(proj, tmp_path):
    p, _ = proj
    seal(p)
    out = tmp_path / "b.zip"
    cli.cmd_export(p, out)
    names = zipfile.ZipFile(out).namelist()
    assert ".riseal/pubkey.pem" in names and "HOW_TO_VERIFY.md" in names
    assert not any(n.endswith(".pem") and "keys" in n for n in names)       # private key never exported
    dest = tmp_path / "unzipped"
    zipfile.ZipFile(out).extractall(dest)
    assert verify(Project(dest))["ok"]                                    # third party verifies straight from the bundle


def test_pae_spec():
    assert pae("t", b"ab") == b"DSSEv1 1 t 2 ab"


# fake secret strings are assembled from pieces so this file never contains anything that looks like a real secret
FAKE_PW_LINE = "DB_" + "PASS" + "WORD=hunter2\n"
FAKE_PEM_HEAD = "-----BEGIN " + "PRIV" + "ATE KEY-----\n"
FAKE_BEARER = "sk-" + "live-" + "XYZ"
PEM_MARK = ("PRIV" + "ATE KEY").encode()


def test_sensitive_paths_redacted_and_content_never_hashed(proj):
    p, _ = proj
    env = "." + "env"
    (p.root / env).write_text(FAKE_PW_LINE)
    (p.root / "keys").mkdir()
    (p.root / "keys" / "prod.pem").write_text(FAKE_PEM_HEAD)
    for f in (env, "keys/prod.pem"):
        _hook(p, {"tool_name": "Read", "tool_input": {"file_path": f}})
    raw = p.receipts.read_text()
    import hashlib
    assert env not in raw and "prod.pem" not in raw
    assert hashlib.sha256((p.root / env).read_bytes()).hexdigest() not in raw
    assert all(x["paths"][0]["path"] == "<redacted>" for x in (r["event"] for r in read_rows(p.receipts)))


def test_user_ignore_file_patterns(proj):
    p, _ = proj
    (p.root / ".risealignore").write_text("# mine\ncustomers/*\n*_contract.pdf\n")
    (p.root / "customers").mkdir()
    (p.root / "customers" / "kim.txt").write_text("x")
    (p.root / "lee_contract.pdf").write_text("x")
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "customers/kim.txt"}})
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "lee_contract.pdf"}})
    raw = p.receipts.read_text()
    assert "kim" not in raw and "lee_contract" not in raw


def test_strict_mode_hides_every_path(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    root = tmp_path / "w"
    root.mkdir()
    (root / "plan.md").write_text("x")
    p = Project(root)
    init(p, key_dir=tmp_path / "h" / ".riseal" / "keys", privacy="strict")
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "plan.md"}})
    item = read_rows(p.receipts)[0]["event"]["paths"][0]
    assert item["path"] == "<redacted>" and "sha256" not in item and len(item["sha256_hmac"]) == 64
    assert "plan.md" not in p.receipts.read_text()


def test_seal_skips_sensitive_files_unless_allowed(proj):
    p, _ = proj
    (p.root / "src" / "api_token.txt").write_text("t")
    r = seal(p, [Path("src")])
    names = {s["name"] for s in json.loads(base64.b64decode(r["envelope"]["payload"]))["subject"]}
    assert "src/api_token.txt" not in names and r["skipped_sensitive"] == ["src/api_token.txt"]
    r2 = seal(p, [Path("src")], allow_sensitive=True)
    assert "src/api_token.txt" in {s["name"] for s in json.loads(base64.b64decode(r2["envelope"]["payload"]))["subject"]}


def test_local_files_are_private(proj):
    p, info = proj
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "src/a.py"}})
    seal(p)
    assert p.receipts.stat().st_mode & 0o777 == 0o600 and p.seals.stat().st_mode & 0o777 == 0o600
    assert p.dir.stat().st_mode & 0o777 == 0o700
    pep = Path(info["key"]).with_suffix(".pepper")
    assert pep.stat().st_mode & 0o777 == 0o600 and p.root not in pep.parents


def test_export_contains_no_secret_material(proj, tmp_path):
    p, info = proj
    _hook(p, {"tool_name": "Bash", "tool_input": {"command": "curl -H 'Authorization: Bearer " + FAKE_BEARER + "'"}})
    seal(p)
    out = tmp_path / "e.zip"
    cli.cmd_export(p, out)
    z = zipfile.ZipFile(out)
    blob = b"".join(z.read(n) for n in z.namelist())
    pep = Path(info["key"]).with_suffix(".pepper").read_bytes()
    assert FAKE_BEARER.encode() not in blob and PEM_MARK not in blob and pep not in blob and pep.hex().encode() not in blob



def test_replaced_public_key_is_detected(proj, tmp_path):
    """A forged bundle: genuine config.json, but pubkey.pem and seals re-signed with another key."""
    p, _ = proj
    seal(p)
    from cryptography.hazmat.primitives import serialization
    from ri_seal.core import Ed25519PrivateKey
    other = Ed25519PrivateKey.generate()
    p.pubkey.write_bytes(other.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    p.seals.write_text("")
    seal(p, sk=other)
    v = verify(p)
    assert not v["ok"] and any("key was replaced" in x for x in v["problems"])


def test_cut_off_tail_keeps_recording_and_is_reported(proj):
    p, _ = proj
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "src/a.py"}})
    with open(p.receipts, "a") as f:
        f.write('{"seq": 1, "prev": "abc')                 # crash in the middle of a write
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "src/a.py"}})
    rows = read_rows(p.receipts)
    assert len(rows) == 2 and rows[1]["prev"] == rows[0]["hash"]        # recording continued, chain intact
    v = verify(p)
    assert any("corrupted" in x for x in v["problems"])                  # but the damage is visible


def test_hook_failure_leaves_a_trace(proj, monkeypatch):
    p, _ = proj
    import ri_seal.cli as c
    monkeypatch.setattr(c, "receipt_from_hook", lambda proj, ev: (_ for _ in ()).throw(OSError("disk")))
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    assert c.cmd_hook(p) == 0
    assert (p.dir / "hook_errors.log").read_text().strip().endswith("OSError")


def test_symlink_to_outside_is_never_sealed(proj, tmp_path):
    p, _ = proj
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("x")
    (p.root / "src" / "link.txt").symlink_to(secret)
    r = seal(p, [Path("src")])
    names = {s["name"] for s in json.loads(base64.b64decode(r["envelope"]["payload"]))["subject"]}
    assert "link.txt" not in names and "src/link.txt" not in names
    assert any("outside project" in x for x in r["skipped_sensitive"])


def test_strict_mode_hides_seal_subject_names(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    root = tmp_path / "w"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "client_kim.md").write_text("x")
    p = Project(root)
    init(p, key_dir=tmp_path / "h" / ".riseal" / "keys", privacy="strict")
    r = seal(p, [Path("docs")])
    assert "client_kim" not in json.dumps(read_rows(p.seals))
    names = [s["name"] for s in json.loads(base64.b64decode(r["envelope"]["payload"]))["subject"]]
    assert names and all(n.startswith("hmac:") or n.startswith(".riseal") for n in names)
    v = verify(p)                                                     # publisher (has pepper): hidden names resolved, not "missing"
    assert v["ok"] and v["files_changed_since_seal"] == [] and v["hidden_subjects_not_checked"] == 0
    (root / "docs" / "client_kim.md").write_text("changed")
    assert verify(p)["files_changed_since_seal"] == ["docs/client_kim.md: changed since seal 0"]


def test_anchor_row_pointing_to_no_seal_is_rejected(proj):
    p, _ = proj
    seal(p)
    from ri_seal.core import append
    append(p.seals, lambda prev, seq: {"seq": seq, "prev": prev, "kind": "anchor", "target": "00" * 32,
                                       "method": "rfc3161", "receipt": "", "detail": {}})
    assert any("points to no seal" in x for x in verify(p)["problems"])


def test_cli_errors_are_friendly(tmp_path, capsys):
    rc = cli.main(["--dir", str(tmp_path), "seal"])
    out = capsys.readouterr().out
    assert rc == 1 and '"ok": false' in out and "Traceback" not in out


def test_missing_fingerprint_in_config_is_a_problem(proj):
    p, _ = proj
    seal(p)
    cfg = json.loads(p.config.read_text())
    cfg.pop("pubkey_sha256")
    p.config.write_text(json.dumps(cfg))
    assert any("no pubkey_sha256" in x for x in verify(p)["problems"])


def test_non_object_tail_does_not_break_hook(proj):
    p, _ = proj
    with open(p.receipts, "a") as f:
        f.write("123\n")
    _hook(p, {"tool_name": "Edit", "tool_input": {"file_path": "src/a.py"}})
    assert len(read_rows(p.receipts)) == 1 and not (p.dir / "hook_errors.log").exists()


def test_preview_signs_nothing_and_coverage_is_signed(proj, capsys):
    p, _ = proj
    (p.root / "src" / "api_token.txt").write_text("t")
    from ri_seal.core import preview
    pv = preview(p, [Path("src")])
    assert pv["coverage"] == {"n_requested": 1, "n_subjects": 1, "n_auto_skipped": 1} and not p.seals.exists() and pv["warnings"] == []
    rc = cli.main(["--dir", str(p.root), "seal", "--preview", "src"])
    assert rc == 0 and not p.seals.exists() and "nothing signed" in capsys.readouterr().out
    r = seal(p, [Path("src")])
    st = json.loads(base64.b64decode(r["envelope"]["payload"]))
    assert st["predicate"]["coverage"] == {"n_requested": 1, "n_subjects": 1, "n_auto_skipped": 1}


def test_third_party_strict_verify_reports_hidden_not_silent(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "h"))
    root = tmp_path / "w"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "client_kim.md").write_text("x")
    p = Project(root)
    init(p, key_dir=tmp_path / "h" / ".riseal" / "keys", privacy="strict")
    seal(p, [Path("docs")])
    import shutil
    bundle = tmp_path / "third"
    shutil.copytree(p.dir, bundle / ".riseal")
    (bundle / "docs").mkdir()
    (bundle / "docs" / "client_kim.md").write_text("CHANGED")
    monkeypatch.setenv("HOME", str(tmp_path / "other_home"))          # no pepper here
    v = verify(Project(bundle))
    assert v["ok"] and v["files_changed_since_seal"] == [] and v["hidden_subjects_not_checked"] == 1
    assert v["note"] and "NOT checked" in v["note"]


def test_preview_warns_when_not_initialised(tmp_path):
    root = tmp_path / "w"
    (root / "a.txt").parent.mkdir(parents=True)
    (root / "a.txt").write_text("x")
    from ri_seal.core import preview
    pv = preview(Project(root), [Path("a.txt")])
    assert pv["coverage"]["n_subjects"] == 1 and any("not initialised" in w for w in pv["warnings"])


def test_anchor_receipt_about_other_seal_is_flagged(proj):
    p, _ = proj
    seal(p)
    from ri_seal.core import append, read_rows
    import base64
    h = [r for r in read_rows(p.seals) if r["kind"] == "seal"][0]["hash"]
    append(p.seals, lambda prev, seq: {"seq": seq, "prev": prev, "kind": "anchor", "target": h, "method": "rfc3161",
                                       "receipt": base64.b64encode(b"junk" * 20).decode(), "detail": {}})
    assert any("not about this seal" in x for x in verify(p)["problems"])
    fake_ots = b"\x00" * 31 + b"\x01\x08" + b"\x11" * 32
    append(p.seals, lambda prev, seq: {"seq": seq, "prev": prev, "kind": "anchor", "target": h, "method": "opentimestamps",
                                       "receipt": base64.b64encode(fake_ots).decode(), "detail": {}})
    assert any("different hash" in x for x in verify(p)["problems"])


def test_expect_seals_catches_cut_tail(proj):
    p, _ = proj
    seal(p)
    seal(p)
    assert verify(p, expect_seals=2)["ok"]
    lines = p.seals.read_text().splitlines()
    p.seals.write_text("\n".join(lines[:1]) + "\n")
    v = verify(p, expect_seals=2)
    assert not v["ok"] and any("seals were removed" in x for x in v["problems"])


def test_subject_outside_project_is_refused_not_read(proj):
    """A bundle signed with its own key may name /etc/hosts or ../x — verify must refuse, not hash files outside the folder."""
    p, _ = proj
    seal(p)
    import base64
    import json as _json
    from ri_seal.core import append, canon, pae, read_rows, load_private, PAYLOAD_TYPE, keyid_of
    sk = load_private(p)
    last = [r for r in read_rows(p.seals) if r["kind"] == "seal"][-1]
    st = _json.loads(base64.b64decode(last["envelope"]["payload"]))
    st["subject"] = [{"name": "/etc/hosts", "digest": {"sha256": "00" * 32}}, {"name": "../../x", "digest": {"sha256": "00" * 32}}]

    def build(prev, seq):
        st["predicate"]["seq"], st["predicate"]["prev"] = seq, prev
        body = canon(st)
        sig = sk.sign(pae(PAYLOAD_TYPE, body))
        return {"seq": seq, "prev": prev, "kind": "seal", "sealed_at": st["predicate"]["sealed_at"], "keyid": last["keyid"],
                "envelope": {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(body).decode(),
                             "signatures": [{"keyid": last["keyid"], "sig": base64.b64encode(sig).decode()}]}}
    append(p.seals, build)
    v = verify(p)
    assert all("etc" not in c for c in v["files_changed_since_seal"])
    assert sum("not a relative path inside the project" in x for x in v["problems"]) == 2


def test_install_hook_default_local_and_shared_bare(proj):
    p, root = proj
    r = cli.cmd_install_claude_hook(p)
    assert r["installed"] and r["settings"].endswith("settings.local.json")
    r2 = cli.cmd_install_claude_hook(p, local=False)
    import json as _json
    shared = _json.loads((p.root / ".claude" / "settings.json").read_text())
    cmd = shared["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    assert r2["installed"] and cmd == "ri-seal hook"


def test_hook_finds_project_from_subdir_cwd(proj, monkeypatch):
    p, _ = proj
    (p.root / "sub").mkdir()
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    import io
    import json as _json
    payload = {"tool_name": "Write", "tool_input": {"file_path": str(p.root / "sub" / "f.txt")}, "cwd": str(p.root / "sub"), "session_id": "s"}
    monkeypatch.setattr("sys.stdin", io.StringIO(_json.dumps(payload)))
    rc = cli.cmd_hook(Project(p.root / "sub"))
    assert rc == 0 and p.receipts.exists() and p.receipts.read_text().strip()


def test_subject_named_like_state_dir_is_still_checked(proj):
    p, _ = proj
    root = p.root
    (root / ".risealignore").write_text("x")
    seal(p, [Path(".risealignore")])
    (root / ".risealignore").write_text("changed")
    assert any(".risealignore" in c for c in verify(p)["files_changed_since_seal"])


def test_verify_exit_code_2_when_files_changed(proj, capsys):
    p, _ = proj
    root = p.root
    (root / "doc.txt").write_text("v1")
    seal(p, [Path("doc.txt")])
    (root / "doc.txt").write_text("v2")
    assert cli.main(["--dir", str(root), "verify"]) == 2
