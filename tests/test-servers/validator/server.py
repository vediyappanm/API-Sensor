#!/usr/bin/env python3
"""Ingest validator — receives APISentinel events and validates them for integration tests."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from collections import defaultdict

# Thread-safe event store
_lock   = threading.Lock()
_events = []
_counts = defaultdict(int)

class ValidatorHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        if self.path == "/ingest":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length)
            try:
                batch = json.loads(body)
                evs   = batch.get("events", [])
                with _lock:
                    _events.extend(evs)
                    for ev in evs:
                        proto = ev.get("protocol", "unknown")
                        _counts[proto] += 1
                self._json(200, {"accepted": len(evs)})
            except Exception as e:
                self._json(400, {"error": str(e)})
        else:
            self._json(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/events":
            with _lock:
                self._json(200, {"events": list(_events), "total": len(_events)})
        elif self.path == "/counts":
            with _lock:
                self._json(200, dict(_counts))
        elif self.path == "/reset":
            with _lock:
                _events.clear()
                _counts.clear()
            self._json(200, {"reset": True})
        elif self.path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not found"})

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    port = int(__import__("os").environ.get("VALIDATOR_PORT", "9999"))
    server = HTTPServer(("0.0.0.0", port), ValidatorHandler)
    print(f"Ingest validator on http://0.0.0.0:{port}")
    print(f"  POST /ingest   — receive event batches")
    print(f"  GET  /events   — retrieve all captured events")
    print(f"  GET  /counts   — event counts by protocol")
    print(f"  GET  /reset    — clear all events")
    server.serve_forever()
