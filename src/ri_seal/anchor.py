"""Optional external anchoring — only runs when you call `ri-seal anchor`.

What is sent: the 32-byte seal hash. Nothing else from your records (the request itself carries your IP and a User-Agent with the tool version) (no file names, no contents).
  * OpenTimestamps public calendars → a .ots proof that later confirms in a Bitcoin block (free; the calendar pays fees).
  * RFC 3161 time-stamp authority (default freetsa.org) → a signed time-stamp token, verifiable with `openssl ts -verify`.
"""
from __future__ import annotations

import base64
import os
import ssl
import urllib.request

from .core import Project, append, now_iso, read_rows

OTS_CALENDARS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]
TSA_URL = "https://freetsa.org/tsr"
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OID_SHA256 = bytes.fromhex("608648016503040201")


def _ctx() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _post(url: str, body: bytes, headers: dict, timeout: int = 30) -> bytes:
    from . import __version__
    req = urllib.request.Request(url, data=body, headers={"User-Agent": f"ri-seal/{__version__}", **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        return r.read()


def ots_file(digest: bytes, calendar_timestamp: bytes) -> bytes:
    if len(digest) != 32:
        raise ValueError("sha256 digest must be 32 bytes")
    return OTS_MAGIC + b"\x01\x08" + digest + calendar_timestamp


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + content


def _der_int(v: int) -> bytes:
    return _der(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big"))


def tsq(digest: bytes, nonce: int) -> bytes:
    alg = _der(0x30, _der(0x06, OID_SHA256) + b"\x05\x00")
    return _der(0x30, _der_int(1) + _der(0x30, alg + _der(0x04, digest)) + _der_int(nonce) + _der(0x01, b"\xff"))


def _der_read(b: bytes, i: int):
    tag, ln, j = b[i], b[i + 1], i + 2
    if ln & 0x80:
        k = ln & 0x7F
        ln, j = int.from_bytes(b[j:j + k], "big"), j + k
    return tag, j, j + ln


def tsr_status(resp: bytes) -> int:
    try:
        t, s, _ = _der_read(resp, 0)
        t2, s2, _ = _der_read(resp, s)
        t3, s3, e3 = _der_read(resp, s2)
    except IndexError as e:
        raise ValueError("truncated TimeStampResp") from e
    if (t, t2, t3) != (0x30, 0x30, 0x02):
        raise ValueError("not a TimeStampResp")
    return int.from_bytes(resp[s3:e3], "big")


def pending(proj: Project, method: str | None = None, calendar: str | None = None) -> list[str]:
    """Seals without an anchor row — per method/calendar, so one calendar succeeding does not hide a failed TSA."""
    rows = read_rows(proj.seals)

    def _done(r):
        if r.get("kind") != "anchor":
            return False
        if method and r.get("method") != method:
            return False
        if calendar and (r.get("detail") or {}).get("calendar") != calendar:
            return False
        return True
    done = {r["target"] for r in rows if _done(r)}
    return [r["hash"] for r in rows if r.get("kind") == "seal" and r["hash"] not in done]


def _record(proj: Project, target: str, method: str, receipt: bytes, detail: dict) -> dict:
    return append(proj.seals, lambda prev, seq: {"seq": seq, "prev": prev, "kind": "anchor", "anchored_at": now_iso(),
                                                 "target": target, "method": method,
                                                 "receipt": base64.b64encode(receipt).decode(), "detail": detail})


def anchor_pending(proj: Project, calendars=None, tsa_url: str | None = TSA_URL, post=_post) -> list[dict]:
    out = []
    proj.proofs.mkdir(parents=True, exist_ok=True)
    for h in pending(proj):                                   # anything missing at least one receipt
        digest = bytes.fromhex(h)
        for cal in calendars or OTS_CALENDARS:
            if h not in pending(proj, "opentimestamps", cal):
                continue
            try:
                proof = ots_file(digest, post(f"{cal}/digest", digest, {"Accept": "application/vnd.opentimestamps.v1"}))
                name = f"{h[:16]}.{cal.split('//')[1].split('.')[0]}.ots"
                (proj.proofs / name).write_bytes(proof)
                _record(proj, h, "opentimestamps", proof, {"calendar": cal, "file": f"proofs/{name}"})
                out.append({"seal": h[:16], "method": "opentimestamps", "calendar": cal, "ok": True})
            except Exception as e:  # noqa: BLE001 — one service failing must not stop the others
                out.append({"seal": h[:16], "method": "opentimestamps", "calendar": cal, "ok": False, "error": str(e)[:160]})
        if tsa_url and h in pending(proj, "rfc3161"):
            try:
                nonce = int.from_bytes(os.urandom(8), "big")
                q = tsq(digest, nonce)
                resp = post(tsa_url, q, {"Content-Type": "application/timestamp-query"})
                st = tsr_status(resp)
                if st not in (0, 1):
                    raise ValueError(f"TSA rejected (status {st})")
                nb = nonce.to_bytes((nonce.bit_length() + 8) // 8, "big")   # DER INTEGER body (sign bit kept)
                if digest not in resp or nb not in resp:
                    raise ValueError("TSA response does not carry our digest/nonce")
                (proj.proofs / f"{h[:16]}.tsq").write_bytes(q)
                (proj.proofs / f"{h[:16]}.tsr").write_bytes(resp)
                _record(proj, h, "rfc3161", resp, {"tsa": tsa_url, "status": st, "nonce": nonce,
                                                   "tsq": base64.b64encode(q).decode()})
                out.append({"seal": h[:16], "method": "rfc3161", "ok": True})
            except Exception as e:  # noqa: BLE001
                out.append({"seal": h[:16], "method": "rfc3161", "ok": False, "error": str(e)[:160]})
    return out
