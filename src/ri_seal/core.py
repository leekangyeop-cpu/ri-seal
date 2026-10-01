"""ri-seal core — tamper-evident receipts for AI-agent work, Ed25519 seals (in-toto Statement v1 + DSSE), verification.

Design rules (why this tool carries little liability):
  * Local only. No server, no telemetry. Nothing leaves the machine unless you run `ri-seal anchor`.
  * Records fingerprints (SHA-256), never file contents or command text.
  * Never blocks the agent: the hook always exits 0 and prints nothing.
  * A seal proves "these records looked like this at that time". It does not prove the records are correct.
"""
from __future__ import annotations

import base64
import fcntl
import fnmatch
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://www.rootinsidegroup.com/ri-seal/seal/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
GENESIS = "0" * 64
STATE_DIR = ".riseal"


# ── primitives ───────────────────────────────────────────────────────

def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pae(payload_type: str, body: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ── project layout ───────────────────────────────────────────────────

class Project:
    def __init__(self, root: Path | str = "."):
        self.root = Path(root).resolve()
        self.dir = self.root / STATE_DIR
        self.receipts = self.dir / "receipts.jsonl"
        self.seals = self.dir / "seals.jsonl"
        self.pubkey = self.dir / "pubkey.pem"
        self.config = self.dir / "config.json"
        self.proofs = self.dir / "proofs"

    def cfg(self) -> dict:
        return json.loads(self.config.read_text("utf-8")) if self.config.exists() else {}

    def key_path(self) -> Path:
        env = os.environ.get("RI_SEAL_KEY")
        if env:
            return Path(env)
        kid = self.cfg().get("keyid")
        if not kid:
            raise FileNotFoundError("not initialised — run `ri-seal init`")
        return Path.home() / ".riseal" / "keys" / f"{kid}.pem"


def keyid_of(pub: Ed25519PublicKey) -> str:
    return sha256_hex(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))[:16]


def init(proj: Project, key_dir: Path | None = None, privacy: str = "standard") -> dict:
    """Create .riseal/ and a signing key kept OUTSIDE the project (~/.riseal/keys, mode 0600). Refuses to overwrite."""
    if privacy not in ("standard", "strict"):
        raise ValueError("privacy must be 'standard' or 'strict'")
    if proj.config.exists():
        raise FileExistsError(f"already initialised: {proj.config}")
    proj.dir.mkdir(parents=True, exist_ok=True)
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    kid = keyid_of(pub)
    key_dir = key_dir or (Path.home() / ".riseal" / "keys")
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir, 0o700)
    kp = key_dir / f"{kid}.pem"
    fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # pepper: a secret 32-byte key, stored next to the signing key (never in the project). Receipts use HMAC with it
    # instead of a plain hash for command text, sensitive paths and (strict mode) everything — so short secrets cannot be
    # recovered from the receipts by guessing.
    pp = key_dir / f"{kid}.pepper"
    fd = os.open(pp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(os.urandom(32))
    os.chmod(proj.dir, 0o700)
    proj.pubkey.write_bytes(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    pub_fp = sha256_hex(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    proj.config.write_text(json.dumps({"version": 1, "keyid": kid, "pubkey_sha256": pub_fp, "created_at": now_iso(),
                                       "privacy": privacy}, indent=2), "utf-8")
    (proj.root / IGNORE_FILE).exists() or (proj.root / IGNORE_FILE).write_text(IGNORE_TEMPLATE, "utf-8")
    gi = proj.dir / ".gitignore"
    gi.write_text("proofs/*.tmp\n", "utf-8")
    return {"keyid": kid, "key": str(kp), "pubkey": str(proj.pubkey), "pubkey_sha256": pub_fp}


def load_private(proj: Project) -> Ed25519PrivateKey:
    kp = proj.key_path()
    if not kp.exists():
        raise FileNotFoundError(f"signing key not found: {kp}")
    if kp.stat().st_mode & 0o077:
        raise PermissionError(f"signing key permissions too open ({oct(kp.stat().st_mode & 0o777)}) — chmod 600 {kp}")
    sk = serialization.load_pem_private_key(kp.read_bytes(), password=None)
    if not isinstance(sk, Ed25519PrivateKey):
        raise TypeError("not an Ed25519 key")
    return sk


def load_public(path: Path) -> Ed25519PublicKey:
    pk = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(pk, Ed25519PublicKey):
        raise TypeError("not an Ed25519 public key")
    return pk


# ── append-only hash chain (shared by receipts and seals) ───────────

def read_rows_checked(path: Path) -> tuple[list[dict], list[int]]:
    """(valid rows, 1-based line numbers that are not valid JSON objects — e.g. a write cut off by a crash)."""
    if not path.exists():
        return [], []
    rows, bad = [], []
    for n, line in enumerate(path.read_text("utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            if not isinstance(r, dict):
                raise ValueError
            rows.append(r)
        except ValueError:
            bad.append(n)
    return rows, bad


def read_rows(path: Path) -> list[dict]:
    return read_rows_checked(path)[0]


def row_hash(row: dict) -> str:
    return sha256_hex(canon({k: v for k, v in row.items() if k != "hash"}))


def append(path: Path, build) -> dict:
    """Lock, check the tail, build(prev_hash, seq) → row, append. Refuses if the tail was edited."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
    with open(path, "a+", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.seek(0)
            text = f.read()
            prev = None
            for line in reversed([l for l in text.splitlines() if l.strip()]):
                try:                                   # skip a corrupt tail (cut-off write); verify reports it
                    cand = json.loads(line)
                except ValueError:
                    continue
                if isinstance(cand, dict):
                    prev = cand
                    break
            if prev is not None and row_hash(prev) != prev.get("hash"):
                raise ValueError(f"last row of {path.name} was modified — run `ri-seal verify`")
            row = build(prev["hash"] if prev else GENESIS, (prev["seq"] + 1) if prev else 0)
            row["hash"] = row_hash(row)
            f.seek(0, os.SEEK_END)
            if text and not text.endswith("\n"):
                f.write("\n")                         # never glue a new row onto a cut-off one
            f.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    return row


def check_chain(rows: list[dict], label: str) -> list[str]:
    probs, prev = [], GENESIS
    for i, r in enumerate(rows):
        if r.get("seq") != i:
            probs.append(f"{label} row {i}: sequence gap")
        if r.get("prev") != prev:
            probs.append(f"{label} row {i}: chain broken")
        if row_hash(r) != r.get("hash"):
            probs.append(f"{label} row {i}: row edited")
        prev = r.get("hash")
    return probs


# ── privacy: what never enters a receipt ────────────────────────────

IGNORE_FILE = ".risealignore"
# Paths that commonly hold secrets or personal data. Their names are replaced by an HMAC and their content is never hashed.
SENSITIVE_DEFAULT = [
    ".env", ".env.*", "*.env", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.kdbx", "*.keystore",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", "*.ppk", ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    "*secret*", "*credential*", "*password*", "*passwd*", "*token*", "*apikey*", "*api_key*",
    ".aws/*", ".ssh/*", ".gnupg/*", ".docker/config.json", ".kube/config", "*.tfstate", "*.tfvars",
    ".riseal/*",
]
IGNORE_TEMPLATE = """# ri-seal: paths matching these patterns are recorded only as an HMAC (name hidden, content never hashed).
# Built-in defaults already cover .env, *.pem, *.key, *secret*, *token*, .ssh/, .aws/ and similar.
# Add your own, one pattern per line, e.g.:
# customers/*
# *_contract.pdf
"""


def _patterns(proj: "Project") -> list[str]:
    extra = []
    f = proj.root / IGNORE_FILE
    if f.exists():
        extra = [l.strip() for l in f.read_text("utf-8").splitlines() if l.strip() and not l.lstrip().startswith("#")]
    return SENSITIVE_DEFAULT + extra


def is_sensitive(rel: str, patterns: list[str]) -> bool:
    low = rel.lower()
    parts = low.split("/")
    for pat in patterns:
        p = pat.lower()
        if fnmatch.fnmatch(low, p) or fnmatch.fnmatch(parts[-1], p) or any(fnmatch.fnmatch(x, p) for x in parts):
            return True
        if p.endswith("/*") and (low.startswith(p[:-1]) or f"/{p[:-1]}" in f"/{low}"):
            return True
    return False


def pepper(proj: "Project") -> bytes:
    pp = proj.key_path().with_suffix(".pepper")
    if not pp.exists():
        raise FileNotFoundError(f"pepper missing: {pp}")
    return pp.read_bytes()


def keyed(pep: bytes, text: str) -> str:
    return hmac.new(pep, text.encode("utf-8"), hashlib.sha256).hexdigest()


# ── receipts (one row per agent tool call) ───────────────────────────

PATH_KEYS = ("file_path", "notebook_path", "path")


def receipt_from_hook(proj: Project, event: dict) -> dict:
    """Turn a hook event (Claude Code PostToolUse JSON or any {tool_name, tool_input}) into a receipt row.

    What is stored: tool name; for each path either the project-relative path + SHA-256 of the file after the call, or —
    for sensitive paths (built-in list + .risealignore) and in strict mode — only an HMAC of the path (content never hashed);
    an HMAC (not a plain hash) of command text and session id. File contents, command text and tool output are never stored."""
    pep = pepper(proj)
    strict = proj.cfg().get("privacy") == "strict"
    pats = _patterns(proj)
    tool = str(event.get("tool_name") or event.get("tool") or "unknown")[:64]
    ti = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    paths = []
    for k in PATH_KEYS:
        v = ti.get(k)
        if not (isinstance(v, str) and v):
            continue
        p = Path(v)
        p = p if p.is_absolute() else proj.root / p
        try:
            rel = str(p.resolve().relative_to(proj.root))
        except ValueError:
            paths.append({"path": "<outside-project>", "path_hmac": keyed(pep, str(p))})
            continue
        if strict or is_sensitive(rel, pats):
            item = {"path": "<redacted>", "path_hmac": keyed(pep, rel)}
            if strict and not is_sensitive(rel, pats) and p.is_file():
                item["sha256_hmac"] = keyed(pep, file_sha256(p))
            paths.append(item)
        else:
            paths.append({"path": rel, "sha256": file_sha256(p) if p.is_file() else None})
    ev = {"tool": tool, "paths": paths}
    sess = event.get("session_id")
    if sess:
        ev["session_hmac"] = keyed(pep, str(sess))[:32]
    cmd = ti.get("command")
    if isinstance(cmd, str):
        ev["command_hmac"] = keyed(pep, cmd)
    return append(proj.receipts, lambda prev, seq: {"seq": seq, "prev": prev, "ts": now_iso(), "event": ev})


# ── seals ────────────────────────────────────────────────────────────

def _subjects(proj: Project, extra: list[Path], allow_sensitive: bool = False, skipped: list | None = None):
    """Sensitive-looking files are left out of a seal unless allow_sensitive (their names would appear in the seal)."""
    pats = _patterns(proj)
    strict = proj.cfg().get("privacy") == "strict"
    pep = pepper(proj) if strict else b""
    skipped = skipped if skipped is not None else []
    rec = read_rows(proj.receipts)
    head = {"n": len(rec), "head": rec[-1]["hash"] if rec else None}
    subjects = []
    if rec:
        subjects.append({"name": f"{STATE_DIR}/receipts.jsonl", "digest": {"sha256": rec[-1]["hash"]}})
    for p in extra:
        p = p if p.is_absolute() else proj.root / p
        files = sorted(x for x in p.rglob("*") if x.is_file() and STATE_DIR not in x.parts) if p.is_dir() else [p]
        for x in files:
            try:
                name = str(x.resolve().relative_to(proj.root))
            except ValueError:
                skipped.append(f"{x.name} (outside project or symlink)")
                continue
            try:
                lexical = str(x.absolute().relative_to(proj.root))
            except ValueError:
                lexical = name
            if (is_sensitive(name, pats) or is_sensitive(lexical, pats)) and not allow_sensitive:
                skipped.append(name)
                continue
            if strict:
                name = "hmac:" + keyed(pep, name)
            subjects.append({"name": name, "digest": {"sha256": file_sha256(x)}})
    return subjects, head


def preview(proj: Project, paths: list[Path] | None = None, allow_sensitive: bool = False) -> dict:
    """What `seal` WOULD sign — nothing is signed or written. Lets a person check the list before committing.
    `warnings` says why a real `seal` would fail (not initialised, key missing)."""
    skipped: list[str] = []
    subjects, head = _subjects(proj, list(paths or []), allow_sensitive, skipped)
    warnings = []
    if not proj.config.exists():
        warnings.append("not initialised — run `ri-seal init` before sealing")
    else:
        try:
            if not proj.key_path().exists():
                warnings.append(f"signing key missing: {proj.key_path()}")
        except FileNotFoundError as e:
            warnings.append(str(e))
    return {"subjects": subjects, "receipts": head, "skipped": skipped, "warnings": warnings,
            "coverage": {"n_requested": len(paths or []), "n_subjects": len(subjects), "n_auto_skipped": len(skipped)}}


def seal(proj: Project, paths: list[Path] | None = None, note: str | None = None, sk=None,
         allow_sensitive: bool = False) -> dict:
    sk = sk or load_private(proj)
    kid = keyid_of(sk.public_key())
    skipped: list[str] = []
    subjects, head = _subjects(proj, list(paths or []), allow_sensitive, skipped)
    ts = now_iso()
    # coverage is part of the SIGNED statement. n_requested = paths the publisher chose to seal, n_auto_skipped = items the
    # tool left out automatically (sensitive names, outside project, symlinks). It shows what was asked and what was dropped;
    # it does NOT reveal files the publisher never asked to seal.
    coverage = {"n_requested": len(paths or []), "n_subjects": len(subjects), "n_auto_skipped": len(skipped)}

    def build(prev, seq):
        st = {"_type": STATEMENT_TYPE, "subject": subjects, "predicateType": PREDICATE_TYPE,
              "predicate": {"sealed_at": ts, "seq": seq, "prev": prev, "receipts": head, "note": note, "coverage": coverage}}
        body = canon(st)
        sig = sk.sign(pae(PAYLOAD_TYPE, body))
        return {"seq": seq, "prev": prev, "kind": "seal", "sealed_at": ts, "keyid": kid,
                "envelope": {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(body).decode(),
                             "signatures": [{"keyid": kid, "sig": base64.b64encode(sig).decode()}]}}
    row = append(proj.seals, build)
    row["skipped_sensitive"] = skipped          # returned to the caller only — not stored
    return row


def verify_envelope(env: dict, pub: Ed25519PublicKey) -> tuple[bool, dict | str]:
    body = base64.b64decode(env["payload"])
    kid = keyid_of(pub)
    sigs = [s for s in env.get("signatures", []) if s.get("keyid") == kid]
    if not sigs:
        return False, f"no signature by key {kid}"
    try:
        pub.verify(base64.b64decode(sigs[0]["sig"]), pae(env["payloadType"], body))
    except InvalidSignature:
        return False, "signature does not match"
    return True, json.loads(body)


def _hmac_index(proj: Project) -> dict[str, str]:
    """HMAC(name) → project-relative path for every regular file in the project (strict-mode verify by the publisher)."""
    try:
        pep = pepper(proj)
    except (FileNotFoundError, KeyError):
        return {}
    out = {}
    for x in proj.root.rglob("*"):
        if not x.is_file() or x.is_symlink() or STATE_DIR in x.parts:
            continue
        try:
            rel = str(x.resolve().relative_to(proj.root))
        except ValueError:
            continue
        out[keyed(pep, rel)] = rel
    return out


def pubkey_fingerprint(pub: Ed25519PublicKey) -> str:
    return sha256_hex(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def _safe_subject_path(root: Path, name: str) -> Path | None:
    """Relative, inside root, no symlink escape. None = refuse."""
    if not name or name.startswith(("/", "\\")) or ".." in Path(name).parts:
        return None
    p = (root / name)
    try:
        if not p.resolve().is_relative_to(root.resolve()):
            return None
    except (OSError, RuntimeError):
        return None
    return p


def verify(proj: Project, pub: Ed25519PublicKey | None = None, check_files: bool = True, expect_seals: int | None = None) -> dict:
    pub = pub or load_public(proj.pubkey)
    fp = pubkey_fingerprint(pub)
    hmac_map: dict | None = None
    hidden = 0
    rec, bad_r = read_rows_checked(proj.receipts)
    seals, bad_s = read_rows_checked(proj.seals)
    problems = [f"receipts line {n}: corrupted (not a valid record)" for n in bad_r]
    problems += [f"seals line {n}: corrupted (not a valid record)" for n in bad_s]
    cfg_fp = proj.cfg().get("pubkey_sha256")
    if not cfg_fp:
        problems.append("config.json has no pubkey_sha256 — cannot tie this public key to the publisher")
    elif cfg_fp != fp:
        problems.append("public key does not match config.json pubkey_sha256 — this bundle's key was replaced")
    problems += check_chain(rec, "receipts") + check_chain(seals, "seals")
    seal_hashes = {r["hash"] for r in seals if r.get("kind") == "seal"}
    # Anchor rows are NOT signed by the publisher: this only checks that each receipt is *about* the right seal hash
    # (OTS digest / TSA message imprint). Whether the receipt is genuine is for `ots verify` / `openssl ts -verify`.
    for r in seals:
        if r.get("kind") == "anchor":
            try:
                proof = base64.b64decode(r.get("receipt") or "")
                target = bytes.fromhex(str(r.get("target") or ""))
            except (ValueError, TypeError):
                problems.append(f"anchor {r.get('seq')}: unreadable receipt")
                continue
            if r.get("target") not in seal_hashes:
                problems.append(f"anchor {r.get('seq')}: points to no seal")
            elif r.get("method") == "opentimestamps":
                # .ots layout: 31-byte magic · version 0x01 · sha256 op 0x08 · 32-byte digest (offset 33)
                if proof[31:33] != b"\x01\x08" or proof[33:65] != target:
                    problems.append(f"anchor {r.get('seq')}: .ots proof is for a different hash")
            elif r.get("method") == "rfc3161":
                if len(proof) < 64 or target not in proof:       # messageImprint (sha256 of the seal) must appear in the TSR
                    problems.append(f"anchor {r.get('seq')}: time-stamp token is not about this seal")
            else:
                problems.append(f"anchor {r.get('seq')}: unknown method {r.get('method')!r}")
    changed: list[str] = []
    for r in seals:
        if r.get("kind") != "seal":
            continue
        ok, st = verify_envelope(r["envelope"], pub)
        if not ok:
            problems.append(f"seal {r['seq']}: {st}")
            continue
        pred = st["predicate"]
        if pred.get("seq") != r["seq"] or pred.get("prev") != r["prev"] or pred.get("sealed_at") != r.get("sealed_at"):
            problems.append(f"seal {r['seq']}: signed statement does not match its row")
        h = pred.get("receipts") or {}
        if h.get("n"):
            if len(rec) < h["n"] or rec[h["n"] - 1].get("hash") != h["head"]:
                problems.append(f"seal {r['seq']}: receipts sealed at that time were rewritten or removed")
        if check_files:
            for s in st["subject"]:
                name = s.get("name")
                if not isinstance(name, str) or "\x00" in name or not isinstance(s.get("digest"), dict) or "sha256" not in s["digest"]:
                    problems.append(f"seal {r['seq']}: malformed subject entry — refused")
                    continue
                if name == STATE_DIR or name.startswith(STATE_DIR + "/"):      # the tool's own receipt file, covered by `receipts`
                    continue
                if s["name"].startswith("hmac:"):
                    if hmac_map is None:
                        hmac_map = _hmac_index(proj)
                    if not hmac_map:                   # no pepper here (third party): names are hidden by design
                        hidden += 1
                        continue
                    rel = hmac_map.get(s["name"][5:])
                    if rel is None:
                        changed.append(f"{s['name'][:21]}…: missing since seal {r['seq']} (hidden name)")
                        continue
                    p = proj.root / rel
                    if file_sha256(p) != s["digest"]["sha256"]:
                        changed.append(f"{rel}: changed since seal {r['seq']}")
                    continue
                p = _safe_subject_path(proj.root, s["name"])
                if p is None:                          # a bundle must never make verify read outside its own folder
                    problems.append(f"seal {r['seq']}: subject {s['name'][:80]!r} is not a relative path inside the project — refused")
                    continue
                if not p.exists():
                    changed.append(f"{s['name']}: missing since seal {r['seq']}")
                elif not p.is_file():
                    problems.append(f"seal {r['seq']}: subject {s['name'][:80]!r} is not a regular file — not hashed")
                elif file_sha256(p) != s["digest"]["sha256"]:
                    changed.append(f"{s['name']}: changed since seal {r['seq']}")
    n_seal_rows = sum(r.get("kind") == "seal" for r in seals)
    if expect_seals is not None and n_seal_rows < expect_seals:
        problems.append(f"only {n_seal_rows} seal rows, expected at least {expect_seals} — seals were removed")
    note = (f"{hidden} sealed subject(s) have hidden names (strict mode) and were NOT checked for changes here — "
            "verify documents you received by their SHA-256 (HOW_TO_VERIFY step 5)") if hidden else None
    return {"ok": not problems, "n_receipts": len(rec), "n_seals": sum(r.get("kind") == "seal" for r in seals),
            "n_anchors": sum(r.get("kind") == "anchor" for r in seals), "keyid": keyid_of(pub),
            "pubkey_sha256": fp, "note": note,
            "check_this": "compare pubkey_sha256 with the value the publisher posted on their own website/GitHub",
            "not_checked_here": "whether seal rows were deleted from the tail (compare n_seals with an earlier export or --expect-seals) "
                                "and whether anchor receipts are genuine (ots verify / openssl ts -verify)",
            "problems": problems, "files_changed_since_seal": changed,
            "hidden_subjects_not_checked": hidden}
