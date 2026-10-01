"""ri-seal command line.

  ri-seal init                    create .riseal/ and a signing key (kept in ~/.riseal/keys, never in the project)
  ri-seal install-claude-hook     add the receipt hook to .claude/settings.json (backs up the file first)
  ri-seal hook                    (called by the agent) read a hook event on stdin, append one receipt — never blocks
  ri-seal seal [PATH ...]         sign the receipts so far, plus any files/folders you name (--preview: show, don't sign)
  ri-seal anchor                  optional: fix unanchored seals in Bitcoin (OpenTimestamps) and a time-stamp authority
  ri-seal verify                  check every receipt, seal, signature and sealed file
  ri-seal status                  one-line summary
  ri-seal export OUT.zip          bundle everything a third party needs to verify, with instructions
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

from . import __version__
from .core import STATE_DIR, Project, init, now_iso, preview, read_rows, receipt_from_hook, seal, verify

# installed hook commands end with `ri-seal" hook`, `ri-seal hook` or `-m ri_seal hook` (see _ours in cmd_install_claude_hook)


def hook_command(shared: bool = False) -> str:
    """Local settings get the absolute path (works even when the agent's PATH lacks the venv). Shared settings
    (.claude/settings.json is usually committed) get the bare `ri-seal hook` so no user name or machine path leaks."""
    if shared:
        return "ri-seal hook"
    exe = shutil.which("ri-seal")
    return f'"{exe}" hook' if exe else f'"{sys.executable}" -m ri_seal hook'


def cmd_install_claude_hook(proj: Project, local: bool = True) -> dict:
    """Add a PostToolUse hook (all tools) to .claude/settings.local.json (default) or the shared settings.json (--shared).
    Idempotent; the first original is kept as .bak."""
    settings = proj.root / ".claude" / ("settings.local.json" if local else "settings.json")
    settings.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(settings.read_text("utf-8")) if settings.exists() else {}
    bak = settings.with_suffix(".json.bak")
    if settings.exists() and not bak.exists():
        shutil.copy2(settings, bak)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict) or not isinstance(hooks.setdefault("PostToolUse", []), list):
        return {"installed": False, "reason": f"unexpected hooks format in {settings} — add the hook by hand", "command": hook_command(not local)}
    post = hooks["PostToolUse"]
    def _ours(cmd: str) -> bool:
        return cmd.endswith('ri-seal" hook') or cmd.endswith("ri-seal hook") or cmd.endswith("-m ri_seal hook")
    if any(_ours(str(h.get("command", ""))) for m in post if isinstance(m, dict)
           for h in m.get("hooks", []) if isinstance(h, dict)):
        return {"installed": False, "reason": "already installed", "settings": str(settings)}
    post.append({"matcher": "*", "hooks": [{"type": "command", "command": hook_command(not local), "timeout": 10}]})
    settings.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", "utf-8")
    return {"installed": True, "settings": str(settings)}


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
            with open(proj.dir / "hook_errors.log", "a", encoding="utf-8") as f:
                f.write(f"{now_iso()} {type(e).__name__}\n")
        except Exception:  # noqa: BLE001
            pass
    return 0


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

1. `pip install "git+https://github.com/leekangyeop-cpu/ri-seal"`, unzip the bundle, then run `ri-seal --dir <unzipped-folder> verify`.
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
    i.add_argument("--privacy", choices=["standard", "strict"], default="standard",
                   help="strict: hide every path name (HMAC only). standard: hide only sensitive paths")
    ih = sub.add_parser("install-claude-hook")
    ih.add_argument("--shared", action="store_true", help="write the shared .claude/settings.json with a bare `ri-seal hook` (needs ri-seal on PATH) instead of settings.local.json")
    ih.add_argument("--local", action="store_true", help="(default) write .claude/settings.local.json with an absolute path")
    sub.add_parser("hook")
    s = sub.add_parser("seal")
    s.add_argument("paths", nargs="*")
    s.add_argument("--note")
    s.add_argument("--allow-sensitive", action="store_true", help="include files that look like secrets (not recommended)")
    s.add_argument("--preview", action="store_true", help="show what would be sealed; sign nothing")
    sub.add_parser("anchor")
    vf = sub.add_parser("verify")
    vf.add_argument("--expect-seals", type=int, default=None, help="fail if fewer seal rows than this (catches a cut-off seals file)")
    sub.add_parser("status")
    e = sub.add_parser("export")
    e.add_argument("out")
    a = ap.parse_args(argv)
    proj = Project(a.dir)

    if a.cmd == "hook":
        return cmd_hook(proj)
    try:
        return _run(a, proj)
    except (FileNotFoundError, FileExistsError, PermissionError, ValueError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False, indent=2))
        return 1


def _run(a, proj: Project) -> int:
    if a.cmd == "init":
        res = init(proj, privacy=a.privacy)
        res["next"] = ("Back up the key file somewhere offline. Publish pubkey_sha256 on your website/GitHub. "
                       "Then: ri-seal install-claude-hook")
    elif a.cmd == "install-claude-hook":
        res = cmd_install_claude_hook(proj, local=not a.shared)
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
        if res["ok"] and res.get("files_changed_since_seal"):
            print(json.dumps(res, ensure_ascii=False, indent=2))
            return 2                                   # chain intact but sealed files changed since — scripts must not treat as clean
    elif a.cmd == "status":
        rows = read_rows(proj.seals)
        rec = read_rows(proj.receipts)
        errs = proj.dir / "hook_errors.log"
        res = {"receipts": len(rec), "last_receipt": rec[-1]["ts"] if rec else None,
               "hook_errors": len(errs.read_text().splitlines()) if errs.exists() else 0,
               "seals": sum(r.get("kind") == "seal" for r in rows),
               "anchors": sum(r.get("kind") == "anchor" for r in rows), "keyid": proj.cfg().get("keyid")}
    else:
        res = cmd_export(proj, Path(a.out))
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
