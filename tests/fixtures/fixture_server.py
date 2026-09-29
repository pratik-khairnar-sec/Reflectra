#!/usr/bin/env python3
"""
tests/fixtures/fixture_server.py
-----------------------------------
Minimal, dependency-free HTTP server that deliberately reflects query
parameters into known contexts, for deterministic Reflectra testing
without depending on a third-party public target.

Run standalone:
    python3 tests/fixtures/fixture_server.py [port]   # default port 8099

Endpoints:
    /html?v=...    reflects `v` into an HTML text node, unescaped
                     -> dialog-confirmable with e.g. <script>alert(1)</script>
    /attr?v=...    reflects `v` into a double-quoted attribute value
                     -> dialog-confirmable with e.g. "><script>alert(1)</script>
    /js?v=...      reflects `v` into an inline <script> string literal
                     -> dialog-confirmable with e.g. ';alert(1);'
    /safe?v=...    reflects `v` but HTML-escaped -- TRUE NEGATIVE case,
                     must never confirm as vulnerable
    /dom?v=...     does NOT reflect `v` server-side at all; a client-side
                     script writes it into innerHTML from location.search
                     -> tests the "not reflected by HTTP probe, still
                        sampled" path; only a real browser can find this
    /multi?a=..&b=..&c=..   three independent HTML-context params, for
                     verifying parameter isolation (one injected, others
                     must remain untouched in the response)
    /               index listing all of the above

This is intentionally vulnerable. Do not expose it beyond localhost.
"""

from __future__ import annotations

import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


PAGE_WRAP = """<!DOCTYPE html><html><head><title>Reflectra Fixture</title></head><body>
{body}
</body></html>"""


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep test output quiet

    def _params(self):
        qs = urlsplit(self.path).query
        return parse_qs(qs, keep_blank_values=True)

    def _send(self, body: str, status: int = 200):
        encoded = PAGE_WRAP.format(body=body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        path = urlsplit(self.path).path
        params = self._params()
        v = params.get("v", [""])[0]

        if path == "/html":
            # Deliberately unescaped -- HTML text-node context.
            self._send(f"<div id='out'>{v}</div>")

        elif path == "/attr":
            # Deliberately unescaped -- double-quoted attribute context.
            self._send(f'<input id="out" value="{v}" readonly>')

        elif path == "/js":
            # Deliberately unescaped -- inline script string-literal context.
            # NOTE: naive substitution, matches how a real vulnerable app
            # would concatenate user input into a JS string server-side.
            self._send(f'<script>var out = "{v}";</script>')

        elif path == "/safe":
            # Escaped -- true-negative case, must never fire a dialog.
            self._send(f"<div id='out'>{html.escape(v)}</div>")

        elif path == "/dom":
            # No server-side reflection at all -- pure client-side sink.
            self._send(
                "<div id='out'></div>"
                "<script>"
                "var p = new URLSearchParams(location.search);"
                "if (p.has('v')) { document.getElementById('out').innerHTML = p.get('v'); }"
                "</script>"
            )

        elif path == "/multi":
            a = params.get("a", [""])[0]
            b = params.get("b", [""])[0]
            c = params.get("c", [""])[0]
            self._send(f"<div id='a'>{a}</div><div id='b'>{b}</div><div id='c'>{c}</div>")

        elif path == "/":
            self._send(
                "<ul>"
                "<li>/html?v=</li><li>/attr?v=</li><li>/js?v=</li>"
                "<li>/safe?v=</li><li>/dom?v=</li><li>/multi?a=&b=&c=</li>"
                "</ul>"
            )
        else:
            self._send("not found", status=404)


def run(port: int = 8099):
    server = ThreadingHTTPServer(("127.0.0.1", port), FixtureHandler)
    print(f"[fixture] serving on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    run(port)
