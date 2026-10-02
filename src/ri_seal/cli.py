"""ri-seal command line.

  ri-seal init                    create .riseal/ and a signing key (kept in ~/.riseal/keys, never in the project)
                                  0.2: privacy defaults to strict (every path name HMAC only); --privacy normal to lower
  ri-seal install-claude-hook     add the receipt hook (PostToolUse) and the claim check (Stop) — shows a preview first
  ri-seal uninstall-claude-hook   remove exactly those two entries, keep every other hook — shows a preview first
  ri-seal hook                    (called by the agent) read a hook event on stdin, append one receipt — never blocks
  ri-seal claim-hook              (called by the agent at Stop) compare "done/passed" claims with receipts — never blocks
  ri-seal seal [PATH ...]         sign the receipts so far, plus any files/folders you name (--preview: show, don't sign)
  ri-seal anchor                  optional: fix unanchored seals in Bitcoin (OpenTimestamps) and a time-stamp authority
  ri-seal verify                  check every receipt, seal, signature and sealed file
  ri-seal status                  three pillars: security · efficiency · accuracy (--details: file:line for each number)
  ri-seal ui                      the same screen as a read-only page on http://127.0.0.1:8765 (Ctrl+C to stop)
  ri-seal export OUT.zip          bundle everything a third party needs to verify, with instructions
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import sys
import zipfile
from pathlib import Path

from . import __version__
from .core import STATE_DIR, Project, append, init, now_iso, preview, receipt_from_hook, seal, verify

# installed hook commands end with `ri-seal" hook`, `ri-seal hook` or `-m ri_seal hook` (and the same with `claim-hook`)
SUBCOMMANDS = {"PostToolUse": "hook", "Stop": "claim-hook"}


def hook_command(shared: bool = False, sub: str = "hook") -> str:
    """Local settings get the absolute path (works even when the agent's PATH lacks the venv). Shared settings
    (.claude/settings.json is usually committed) get the bare `ri-seal hook` so no user name or machine path leaks."""
    if shared:
        return f"ri-seal {sub}"
    exe = shutil.which("ri-seal")
    return f'"{exe}" {sub}' if exe else f'"{sys.executable}" -m ri_seal {sub}'


def is_ours(cmd: str, sub: str) -> bool:
    """Exactly the three shapes hook_command() writes (0.1 wrote the same shapes) — nothing that merely ends alike:
    `ri-seal SUB`, `"/abs/path/ri-seal" SUB`, `"/abs/path/python" -m ri_seal SUB`."""
    return re.fullmatch(rf'ri-seal {re.escape(sub)}|"[^"]*/ri-seal" {re.escape(sub)}|"[^"]+" -m ri_seal {re.escape(sub)}',
                        cmd.strip()) is not None


def _log_hook_error(proj: Project, line: str) -> None:
    """hook_errors.log is created 0600 like the other record files."""
    fd = os.open(proj.dir / "hook_errors.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(fd, 0o600)                              # also tightens a log left 0644 by 0.1
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def _settings_path(proj: Project, local: bool) -> Path:
    return proj.root / ".claude" / ("settings.local.json" if local else "settings.json")


def _diff(before: str, after: str, name: str) -> list[str]:
    return list(difflib.unified_diff(before.splitlines(), after.splitlines(), f"{name} (before)", f"{name} (after)",
                                     lineterm="", n=2))


def cmd_install_claude_hook(proj: Project, local: bool = True, claim_hook: bool = True, dry_run: bool = False) -> dict:
    """Add a PostToolUse hook (all tools) and — unless claim_hook=False — a Stop hook (`ri-seal claim-hook`) to
    .claude/settings.local.json (default) or the shared settings.json (--shared). Idempotent; the first original is kept
    as .bak. `preview` (a unified diff) is returned before anything is written; dry_run writes nothing."""
    settings = _settings_path(proj, local)
    before = settings.read_text("utf-8") if settings.exists() else ""
    data = json.loads(before) if before.strip() else {}
    hooks = data.setdefault("hooks", {}) if isinstance(data, dict) else None
    wanted = ["PostToolUse"] + (["Stop"] if claim_hook else [])
    if not isinstance(hooks, dict) or any(not isinstance(hooks.setdefault(ev, []), list) for ev in wanted):
        return {"installed": False, "reason": f"unexpected hooks format in {settings} — add the hook by hand",
                "command": hook_command(not local)}
    added = []
    for ev in wanted:
        sub = SUBCOMMANDS[ev]
        if any(is_ours(str(h.get("command", "")), sub) for m in hooks[ev] if isinstance(m, dict)
               for h in m.get("hooks", []) if isinstance(h, dict)):
            continue
        entry = {"hooks": [{"type": "command", "command": hook_command(not local, sub), "timeout": 10 if ev == "PostToolUse" else 15}]}
        if ev == "PostToolUse":
            entry = {"matcher": "*", **entry}
        hooks[ev].append(entry)
        added.append(ev)
    if not added:
        return {"installed": False, "reason": "already installed", "settings": str(settings), "preview": []}
    after = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    res = {"installed": not dry_run, "added": added, "settings": str(settings), "preview": _diff(before, after, settings.name)}
    if dry_run:
        res["reason"] = "dry run — nothing written"
        return res
    settings.parent.mkdir(parents=True, exist_ok=True)
    bak = settings.with_suffix(".json.bak")
    if settings.exists() and not bak.exists():
        shutil.copy2(settings, bak)
    settings.write_text(after, "utf-8")
    return res


def cmd_uninstall_claude_hook(proj: Project, local: bool = True, dry_run: bool = False) -> dict:
    """Remove only the entries ri-seal installed (its `hook` under PostToolUse, its `claim-hook` under Stop). Other hooks —
    including other commands that share a matcher group with ours — are kept. A group or event list left empty by the
    removal is dropped; nothing else is touched."""
    settings = _settings_path(proj, local)
    if not settings.exists():
        return {"removed": 0, "reason": "settings file not found", "settings": str(settings), "preview": []}
    before = settings.read_text("utf-8")
    data = json.loads(before) if before.strip() else {}
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return {"removed": 0, "reason": "no hooks in settings", "settings": str(settings), "preview": []}
    removed = 0
    for ev, sub in SUBCOMMANDS.items():
        groups = hooks.get(ev)
        if not isinstance(groups, list):
            continue
        new_groups = []
        for g in groups:
            if not isinstance(g, dict) or not isinstance(g.get("hooks"), list):
                new_groups.append(g)
                continue
            keep = [h for h in g["hooks"] if not (isinstance(h, dict) and is_ours(str(h.get("command", "")), sub))]
            removed += len(g["hooks"]) - len(keep)
            if keep:
                new_groups.append({**g, "hooks": keep})
            elif not g["hooks"]:
                new_groups.append(g)                      # an empty group that was not ours — leave it as it was
        if new_groups:
            hooks[ev] = new_groups
        elif groups:
            del hooks[ev]
    if not removed:
        return {"removed": 0, "reason": "ri-seal hooks not found", "settings": str(settings), "preview": []}
    if not hooks:
        del data["hooks"]
    after = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    res = {"removed": removed, "settings": str(settings), "preview": _diff(before, after, settings.name)}
    if dry_run:
        res["reason"] = "dry run — nothing written"
        res["removed_would_be"], res["removed"] = removed, 0
        return res
    settings.write_text(after, "utf-8")
    return res


def _find_project(start: Path, payload: dict) -> Project | None:
    """The hook may run with any cwd: try the event's cwd, $CLAUDE_PROJECT_DIR, then walk up from `start`."""
    cands = [payload.get("cwd"), os.environ.get("CLAUDE_PROJECT_DIR"), str(start)]
    for c in cands:
        if not c:
            continue
        p = Path(c)
        for d in (p, *p.parents):
            if (d / STATE_DIR / "config.json").exists():
                return Project(d)
    return None


def cmd_hook(proj: Project) -> int:
    """Hook entry point: must never break the agent, so every failure is swallowed and exit code is always 0."""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        found = proj if proj.config.exists() else _find_project(proj.root, payload)
        if found is not None:
            receipt_from_hook(found, payload)
    except BaseException as e:  # noqa: BLE001 — never break the agent; leave a trace instead of failing silently
        try:
            _log_hook_error(proj, f"{now_iso()} {type(e).__name__}")
        except Exception:  # noqa: BLE001
            pass
    return 0


def cmd_claim_hook(proj: Project) -> int:
    """Stop-hook entry point (measurement only). Never blocks: always exit 0, prints nothing on stdout (a Stop hook's
    stdout could be read as a decision), and on failure writes one line to stderr and to hook_errors.log."""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            raise ValueError("hook input is not an object")
        found = proj if proj.config.exists() else _find_project(proj.root, payload)
        if found is not None:
            from .claims import last_assistant_text, record
            text = last_assistant_text(payload)
            if text.strip():
                record(found, text, payload.get("session_id"), source="hook")
    except BaseException as e:  # noqa: BLE001
        try:
            sys.stderr.write(f"ri-seal claim-hook: {type(e).__name__} (ignored)\n")
            _log_hook_error(proj, f"{now_iso()} claim-hook {type(e).__name__}")
        except Exception:  # noqa: BLE001
            pass
    return 0


def record_verify(proj: Project, res: dict, code: int) -> None:
    """Keep the result of each CLI verify for `status` (counts only). Never fails the verify itself."""
    try:
        if proj.config.exists():
            append(proj.verify_log, lambda prev, seq: {
                "seq": seq, "prev": prev, "ts": now_iso(), "ok": bool(res.get("ok")), "exit": code,
                "n_problems": len(res.get("problems") or []), "n_changed": len(res.get("files_changed_since_seal") or []),
                "n_receipts": res.get("n_receipts"), "n_seals": res.get("n_seals")})
    except Exception:  # noqa: BLE001
        pass


def cmd_export(proj: Project, out: Path) -> dict:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in (proj.pubkey, proj.config, proj.receipts, proj.seals):
            if p.exists():
                z.write(p, f".riseal/{p.name}")
        if proj.proofs.exists():
            for p in sorted(proj.proofs.iterdir()):
                z.write(p, f".riseal/proofs/{p.name}")
        z.writestr("HOW_TO_VERIFY.md", VERIFY_GUIDE)
    return {"bundle": str(out)}


VERIFY_GUIDE = """# How to verify this bundle

1. Install ri-seal pinned to a release — a commit hash from the GitHub release page, or the release tag:
   `pip install "git+https://github.com/leekangyeop-cpu/ri-seal@<commit-hash>"` (or `...@v0.2.0`).
   Or download the release wheel and check it first: `shasum -a 256 -c SHA256SUMS`, then `pip install <wheel>`.
   Unzip the bundle, then run `ri-seal --dir <unzipped-folder> verify`.
   (compare the printed pubkey_sha256 with the publisher's website; `--expect-seals N` if they told you how many seals to expect)
   It prints `pubkey_sha256`. Get the publisher's public-key fingerprint from at least two of THEIR OWN channels
   (website, GitHub, LinkedIn) and compare. If it differs, stop — do not trust the bundle's own files for this step.
   Sealed documents you also received can be placed in that folder at their listed paths to be checked too.
   Subjects named `hmac:…` (strict mode) are hidden by design and are not checked by third parties.
2. Bitcoin time: easiest is the web verifier at opentimestamps.org with `.riseal/proofs/X.ots`;
   or `pip install opentimestamps-client`, `ots upgrade .riseal/proofs/X.ots`, then `ots verify -d <seal hash> .riseal/proofs/X.ots`
   (needs a Bitcoin node; the seal hash is the `hash` of the seal row in .riseal/seals.jsonl).
3. Time-stamp authority: `openssl ts -verify -queryfile .riseal/proofs/X.tsq -in .riseal/proofs/X.tsr -CAfile cacert.pem -untrusted tsa.crt`
   (certificates from the authority's website).
4. Our signature: the seal rows carry a DSSE envelope (in-toto Statement v1) — any DSSE verifier can check it against pubkey.pem.
   The receipt/seal hash chains are ri-seal's own format; `ri-seal verify` checks those.
5. To check a document: compute its SHA-256 and find it among the sealed subjects (also for `hmac:` subjects you cannot name).

A seal proves the records looked like this at that time. It does not prove they are correct.

Privacy: receipts never contain file contents, command text or tool output. Paths that look sensitive (.env, keys,
*secret*, *token*, .ssh/, .aws/ ... and the publisher's .risealignore) appear only as an HMAC, which cannot be reversed
without the publisher's secret pepper. In strict mode every path is shown that way.
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ri-seal", description="Tamper-evident receipts and seals for AI-agent work.")
    ap.add_argument("--dir", default=".", help="project folder (default: current)")
    ap.add_argument("--version", action="version", version=f"ri-seal {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init")
    i.add_argument("--privacy", choices=["strict", "normal", "standard"], default="strict",
                   help="strict (default): hide every path name (HMAC only). normal: hide only sensitive-looking paths "
                        "(`standard` is the 0.1 name for normal)")
    ih = sub.add_parser("install-claude-hook")
    ih.add_argument("--shared", action="store_true", help="write the shared .claude/settings.json with a bare `ri-seal hook` (needs ri-seal on PATH) instead of settings.local.json")
    ih.add_argument("--local", action="store_true", help="(default) write .claude/settings.local.json with an absolute path")
    ih.add_argument("--no-claim-hook", action="store_true", help="do not add the Stop hook that compares claims with receipts")
    ih.add_argument("--dry-run", action="store_true", help="show the change; write nothing")
    uh = sub.add_parser("uninstall-claude-hook")
    uh.add_argument("--shared", action="store_true", help="remove from the shared .claude/settings.json instead of settings.local.json")
    uh.add_argument("--dry-run", action="store_true", help="show the change; write nothing")
    sub.add_parser("hook")
    sub.add_parser("claim-hook")
    s = sub.add_parser("seal")
    s.add_argument("paths", nargs="*")
    s.add_argument("--note")
    s.add_argument("--allow-sensitive", action="store_true", help="include files that look like secrets (not recommended)")
    s.add_argument("--preview", action="store_true", help="show what would be sealed; sign nothing")
    sub.add_parser("anchor")
    vf = sub.add_parser("verify")
    vf.add_argument("--expect-seals", type=int, default=None, help="fail if fewer seal rows than this (catches a cut-off seals file)")
    st = sub.add_parser("status")
    st.add_argument("--lang", choices=["ko", "en"], default=None, help="screen language (default: from $LANG)")
    st.add_argument("--details", action="store_true", help="show the file and line numbers behind every number")
    st.add_argument("--json", action="store_true", help="machine-readable output")
    u = sub.add_parser("ui")
    u.add_argument("--port", type=int, default=8765)
    u.add_argument("--lang", choices=["ko", "en"], default=None)
    e = sub.add_parser("export")
    e.add_argument("out")
    a = ap.parse_args(argv)
    proj = Project(a.dir)

    if a.cmd == "hook":
        return cmd_hook(proj)
    if a.cmd == "claim-hook":
        return cmd_claim_hook(proj)
    try:
        return _run(a, proj)
    except (FileNotFoundError, FileExistsError, PermissionError, ValueError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False, indent=2))
        return 1


def _run(a, proj: Project) -> int:
    if a.cmd == "init":
        res = init(proj, privacy=a.privacy)
        res["privacy"] = proj.cfg().get("privacy")
        res["next"] = ("Back up the key file somewhere offline. Publish pubkey_sha256 on your website/GitHub. "
                       "Then: ri-seal install-claude-hook")
    elif a.cmd in ("install-claude-hook", "uninstall-claude-hook"):
        if a.cmd == "install-claude-hook":
            res = cmd_install_claude_hook(proj, local=not a.shared, claim_hook=not a.no_claim_hook, dry_run=a.dry_run)
        else:
            res = cmd_uninstall_claude_hook(proj, local=not a.shared, dry_run=a.dry_run)
        diff = res.pop("preview", [])
        if diff:
            print("\n".join(diff))
            print()
    elif a.cmd == "status":
        from .status import compute, default_lang, render_text
        d = compute(proj)
        if a.json:
            print(json.dumps(d, ensure_ascii=False, indent=2))
        else:
            print(render_text(d, a.lang or default_lang(), details=a.details, color=sys.stdout.isatty()))
        return 0
    elif a.cmd == "ui":
        from .status import default_lang
        from .ui import serve
        return serve(proj, a.port, a.lang or default_lang())
    elif a.cmd == "seal" and a.preview:
        res = preview(proj, [Path(p) for p in a.paths], allow_sensitive=a.allow_sensitive)
        res["note"] = "preview only — nothing signed. Run again without --preview to seal."
    elif a.cmd == "seal":
        r = seal(proj, [Path(p) for p in a.paths], a.note, allow_sensitive=a.allow_sensitive)
        res = {"seal": r["hash"][:16], "seq": r["seq"], "sealed_at": r["sealed_at"]}
        if r.get("skipped_sensitive"):
            res["skipped_sensitive"] = r["skipped_sensitive"]
            res["why"] = "these look like secrets; their names would be visible in the seal. Use --allow-sensitive to include."
    elif a.cmd == "anchor":
        from .anchor import anchor_pending
        res = {"results": anchor_pending(proj)}
        res["ok"] = all(x["ok"] for x in res["results"])
    elif a.cmd == "verify":
        res = verify(proj, expect_seals=a.expect_seals)
        code = 2 if res["ok"] and res.get("files_changed_since_seal") else (0 if res["ok"] else 1)
        record_verify(proj, res, code)
        if code == 2:
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 2                                   # chain intact but sealed files changed since — scripts must not treat as clean
    else:
        res = cmd_export(proj, Path(a.out))
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
