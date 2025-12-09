"""Tiny HTTP API to expose FIM events from the JSONL log."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import List, Tuple
from urllib.parse import parse_qs, urlparse

LOG_PATH = "events.log"


def load_events(limit: int = 100) -> List[dict]:
    events: List[dict] = []
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    events.append(json.loads(line))
    except FileNotFoundError:
        return []

    events.sort(key=lambda e: e.get("timestamp", ""))
    return events[-limit:]


class Handler(BaseHTTPRequestHandler):
    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/events":
            self._write_json(404, {"error": "not found"})
            return

        params = parse_qs(parsed.query)
        try:
            limit = int(params.get("limit", ["100"])[0])
        except ValueError:
            limit = 100
        limit = max(1, min(limit, 500))

        events = load_events(limit)
        self._write_json(200, {"events": events})

    def log_message(self, format, *args):  # noqa: A003
        return  # Silence default logging


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = HTTPServer((host, port), Handler)
    print(f"Serving events from {LOG_PATH} on http://{host}:{port}/events")
    server.serve_forever()


if __name__ == "__main__":
    run()
