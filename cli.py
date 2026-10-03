"""CLI for prompt-injection-firewall.

    python3 cli.py scan <file>        scan a file of tool output, print findings
    python3 cli.py scan <file> --json machine-readable findings
    python3 cli.py check <file>       CI gate: exit 0 clean, 1 sanitize, 2 block
    python3 cli.py demo               one-command end-to-end agent-loop demo
    python3 cli.py serve [--port N]   tiny JSON API: POST /scan {"tool","output"}

Exit codes for `check` (CI-friendly):
    0 = clean (ALLOW)   1 = findings, worst action SANITIZE   2 = BLOCK
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from firewall import (  # noqa: E402
    Firewall,
    Policy,
    decide_on_text,
    scan,
    wrap_tool_output,
)

EXIT_CLEAN = 0
EXIT_SANITIZE = 1
EXIT_BLOCK = 2


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def cmd_scan(path: str, as_json: bool = False) -> int:
    text = _read_input(path)
    result = scan(text)
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    if not result.findings:
        print("clean: no injection markers found")
        return 0
    print(f"flagged: {len(result.findings)} finding(s), "
          f"max severity {result.max_severity}")
    for f in result.findings:
        print(f"  [{f.severity:6s}] {f.category} ({f.rule_id})")
        print(f"           evidence: {f.evidence!r}")
        print(f"           why: {f.explanation}")
    return 0


def cmd_check(path: str) -> int:
    text = _read_input(path)
    decision = decide_on_text(text, scan(text), Policy())
    print(f"{decision.action.upper()}: {len(decision.findings)} finding(s)")
    for reason in decision.reasons:
        print(f"  - {reason}")
    if decision.action == "block":
        return EXIT_BLOCK
    if decision.action == "sanitize":
        return EXIT_SANITIZE
    return EXIT_CLEAN


def cmd_demo() -> int:
    import demo

    return demo.main()


# ---------------------------------------------------------------------------
# serve: tiny stdlib JSON API
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    firewall = Firewall()

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, {
                "service": "prompt-injection-firewall",
                "usage": "POST /scan with JSON {\"tool\": \"name\", "
                         "\"output\": \"tool output text\"}",
            })
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/scan":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid JSON"})
            return
        tool = payload.get("tool", "unknown")
        output = payload.get("output")
        if not isinstance(output, str):
            self._send(400, {"error": "field 'output' must be a string"})
            return
        try:
            decision = self.firewall.scan_wrapped(wrap_tool_output(str(tool), output))
        except Exception as exc:  # boundary validation etc.
            self._send(400, {"error": str(exc)})
            return
        self._send(200, decision.to_dict())

    def log_message(self, *args):  # keep serve output quiet
        pass


def make_server(port: int = 8091) -> HTTPServer:
    return HTTPServer(("127.0.0.1", port), _Handler)


def cmd_serve(port: int) -> int:
    server = make_server(port)
    print(f"prompt-injection-firewall serving on 127.0.0.1:{port} "
          f"(POST /scan {{\"tool\": ..., \"output\": ...}})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cli.py",
                                     description="prompt-injection firewall")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file of tool output for injections")
    s.add_argument("path", help="file to scan ('-' for stdin)")
    s.add_argument("--json", action="store_true",
                   help="machine-readable output")

    c = sub.add_parser("check", help="CI gate: exit 0 clean / 1 sanitize / 2 block")
    c.add_argument("path", help="file to check ('-' for stdin)")

    sub.add_parser("demo", help="one-command end-to-end demo")

    v = sub.add_parser("serve", help="tiny JSON API (POST /scan)")
    v.add_argument("--port", type=int, default=8091)

    args = parser.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args.path, as_json=args.json)
    if args.cmd == "check":
        return cmd_check(args.path)
    if args.cmd == "demo":
        return cmd_demo()
    if args.cmd == "serve":
        return cmd_serve(args.port)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
