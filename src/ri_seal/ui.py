"""`ri-seal ui` — one read-only page on 127.0.0.1 (standard library http.server). Ctrl+C stops it.

* Binds to 127.0.0.1 only — the address is fixed in code, not an option.
* GET / and HEAD / only; everything else is 404/405. No forms, no state changes, no JavaScript, no external requests
  (inline CSS; Content-Security-Policy `default-src 'none'`).
* Rejects requests whose Host header is not 127.0.0.1/localhost (blocks DNS-rebinding pages from reading it).
* Shows counts and file:line references only — never claim text or path names.
"""
from __future__ import annotations

import signal
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import Project
from .status import compute, render_html

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; "
                               "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def make_server(proj: Project, port: int = DEFAULT_PORT, lang: str = "ko") -> ThreadingHTTPServer:
    allowed_hosts: set[str] = set()

    class Handler(BaseHTTPRequestHandler):
        server_version = "ri-seal-ui"
        sys_version = ""

        def log_message(self, fmt, *args):            # quiet: no request log on the terminal or on disk
            pass

        def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8", head: bool = False):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _page(self, head: bool):
            if (self.headers.get("Host") or "") not in allowed_hosts:
                return self._send(421, b"misdirected request\n", head=head)
            if self.path.split("?", 1)[0] != "/":
                return self._send(404, b"not found\n", head=head)
            try:
                body = render_html(compute(proj), lang).encode("utf-8")
            except Exception as e:  # noqa: BLE001 — show the error class, never a traceback with paths
                return self._send(500, f"could not read records: {type(e).__name__}\n".encode(), head=head)
            return self._send(200, body, "text/html; charset=utf-8", head=head)

        def do_GET(self):
            self._page(False)

        def do_HEAD(self):
            self._page(True)

        def _refuse(self):
            self._send(405, b"read-only\n")

        do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _refuse

    srv = ThreadingHTTPServer((HOST, port), Handler)
    real_port = srv.server_address[1]
    # with or without the port (some clients omit the default-looking port); any other name is refused (DNS rebinding)
    allowed_hosts.update({f"{HOST}:{real_port}", f"localhost:{real_port}", HOST, "localhost"})
    return srv


def _stop(signum, frame):
    raise KeyboardInterrupt


def serve(proj: Project, port: int = DEFAULT_PORT, lang: str = "ko") -> int:
    # Ctrl+C must always stop the server — even when started from a shell that left SIGINT ignored. SIGTERM too.
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):                 # not in the main thread
            pass
    srv = make_server(proj, port, lang)
    url = f"http://{HOST}:{srv.server_address[1]}/"
    msg = (f"ri-seal ui — {url} (이 컴퓨터에서만 열립니다. 끝내려면 Ctrl+C)" if lang == "ko"
           else f"ri-seal ui — {url} (this computer only. Ctrl+C to stop)")
    print(msg, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("", file=sys.stderr)
    finally:
        srv.server_close()
    return 0
