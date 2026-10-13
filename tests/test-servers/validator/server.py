#!/usr/bin/env python3
"""Ingest validator — validates the real APISentinel sensor wire contract (audit F20).

The production sensor (userspace/src/ingest.rs + userspace/src/output.rs) posts a
`SensorBatch` envelope:

    {"MsgHeader": {"Version": "2.0", "MessageTime": "...", "TenantId": "...",
                   "Sequence": 1, "InternalOPCID": "...", "PolicyVersion": "1"},
     "Batch": [ {flat dotted-key event}, ... ]}

Batch payloads larger than the sensor's 4096-byte compression threshold arrive
gzip-compressed (`Content-Encoding: gzip`).

This validator REJECTS (4xx) any request that does not match that contract —
including the legacy nested `{"events": [...]}` schema — so a schema regression
cannot silently pass with zero accepted events (audit F20).

Request-ID oracle: integration tests embed a unique `rid=<id>` query parameter in
each generated request; the captured event carries it in `HTTPReq.Query` /
`HTTPReq.Uri`. `GET /events?rid=<id>` returns only matching events, so tests can
correlate their own traffic without resetting shared state.

Env config: VALIDATOR_PORT (9999), VALIDATOR_MAX_BODY_BYTES (32 MiB),
VALIDATOR_MAX_DECOMPRESSED_BYTES (128 MiB), VALIDATOR_MAX_STORED (100000).
"""
import json
import os
import threading
import time
import zlib
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

SCHEMA_VERSION = "sensor-batch-v2.0"

PORT = int(os.environ.get("VALIDATOR_PORT", "9999"))
MAX_BODY_BYTES = int(os.environ.get("VALIDATOR_MAX_BODY_BYTES", str(32 * 1024 * 1024)))
MAX_DECOMPRESSED_BYTES = int(os.environ.get("VALIDATOR_MAX_DECOMPRESSED_BYTES", str(128 * 1024 * 1024)))
MAX_STORED_EVENTS = int(os.environ.get("VALIDATOR_MAX_STORED", "100000"))

# MsgHeader fields and their required JSON types (name -> python type).
REQUIRED_HEADER_FIELDS = {
    "Version": str,
    "MessageTime": str,
    "TenantId": str,
    "Sequence": int,
    "InternalOPCID": str,
    "PolicyVersion": str,
}

# Per-event dotted keys emitted by userspace/src/output.rs `event_to_value`.
REQUIRED_EVENT_FIELDS = {
    "SrcInfo.Source": int,
    "LogVersion": str,
    "Id": str,
    "SessionStats.StartTime": str,
    "L7Protocol": str,
    "HTTPReq.Method": str,
    "HTTPReq.Uri": str,
    "HTTPReq.Query": str,
    "HTTPReq.BodyLength": int,
    "HTTPResp.ResponseCode": int,
    "DownstreamL3L4.SourceIP": str,
    "DownstreamL3L4.DestIP": str,
    "DownstreamL3L4.SourcePort": int,
    "DownstreamL3L4.DestPort": int,
    "Proto": str,
    "APIID": int,
    "MetaDataMap": dict,
}

VALID_L7_PROTOCOLS = {"HTTP11", "HTTP2", "HTTP3", "GRPC", "WebSocket", "QUIC", "MCP"}

_lock = threading.Lock()
_events = deque()                 # accepted events (bounded by MAX_STORED_EVENTS)
_protocol_counts = Counter()      # L7Protocol -> accepted counts since reset
_accepted_total = 0
_accepted_batches = 0
_rejected_total = 0
_last_rejection = None            # {"time": ..., "status": ..., "error": ...}
_dropped_stored = 0               # events evicted because the store was full


def _type_ok(value, expected):
    if expected is int:
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, expected)


def validate_envelope(obj):
    """Return (status, error) for a decoded request body. status 0 == valid."""
    if not isinstance(obj, dict):
        return 400, "envelope must be a JSON object with MsgHeader and Batch keys"
    if "events" in obj and "Batch" not in obj:
        return 400, ("legacy nested schema rejected: this sensor emits "
                     "MsgHeader/Batch with flat dotted-key events, not {'events': [...]}"
                     f" (validator schema {SCHEMA_VERSION})")
    if "MsgHeader" not in obj:
        return 400, "missing MsgHeader"
    header = obj["MsgHeader"]
    if not isinstance(header, dict):
        return 400, "MsgHeader must be an object"
    for field, expected in REQUIRED_HEADER_FIELDS.items():
        if field not in header:
            return 400, f"MsgHeader missing field {field!r}"
        if not _type_ok(header[field], expected):
            return 400, f"MsgHeader.{field} must be {expected.__name__}"
    if "Batch" not in obj:
        return 400, "missing Batch"
    batch = obj["Batch"]
    if not isinstance(batch, list):
        return 400, "Batch must be an array of events"
    if not batch:
        return 400, "Batch is empty: the sensor must not submit zero-event batches"
    for i, ev in enumerate(batch):
        if not isinstance(ev, dict):
            return 400, f"Batch[{i}] must be an object with flat dotted keys"
        for field, expected in REQUIRED_EVENT_FIELDS.items():
            if field not in ev:
                return 400, f"Batch[{i}] missing required key {field!r}"
            if not _type_ok(ev[field], expected):
                return 400, (f"Batch[{i}].{field} must be "
                             f"{expected.__name__}, got {type(ev[field]).__name__}")
        proto = ev["L7Protocol"]
        if proto not in VALID_L7_PROTOCOLS:
            return 400, (f"Batch[{i}].L7Protocol {proto!r} not in "
                         f"expected set {sorted(VALID_L7_PROTOCOLS)}")
    return 0, None


def gunzip_limited(data, limit):
    """Decompress gzip data with a hard output cap. Raises zlib.error on garbage."""
    obj = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    out = obj.decompress(data, limit)
    if len(out) >= limit and (obj.unconsumed_tail or obj.unflushed):
        raise zlib.error(f"decompressed size exceeds cap of {limit} bytes")
    out += obj.flush()
    if not obj.eof:
        # zlib happily returns partial output for a truncated stream; a torn
        # batch must be rejected, not silently half-accepted.
        raise zlib.error("truncated gzip stream (no end-of-stream marker)")
    if len(out) > limit:
        raise zlib.error(f"decompressed size exceeds cap of {limit} bytes")
    return out

class ValidatorHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ── POST /ingest ────────────────────────────────────────────────────────
    def do_POST(self):
        global _accepted_total, _accepted_batches, _dropped_stored
        if urlparse(self.path).path != "/ingest":
            self._json(404, {"error": "not found; use POST /ingest"})
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self._reject(400, "missing or invalid Content-Length")
            return
        if length > MAX_BODY_BYTES:
            self._reject(413, f"body of {length} bytes exceeds cap {MAX_BODY_BYTES}")
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._reject(400, f"short read: got {len(body)} of {length} bytes")
            return

        encoding = (self.headers.get("Content-Encoding") or "").lower()
        if "gzip" in encoding or body[:2] == b"\x1f\x8b":
            try:
                body = gunzip_limited(body, MAX_DECOMPRESSED_BYTES)
            except Exception as e:  # noqa: BLE001 — report any decompression failure
                self._reject(400, f"gzip decompression failed: {e}")
                return

        try:
            envelope = json.loads(body)
        except Exception as e:  # noqa: BLE001
            self._reject(400, f"invalid JSON: {e}")
            return

        status, error = validate_envelope(envelope)
        if status != 0:
            self._reject(status, error)
            return

        events = envelope["Batch"]
        sequence = envelope["MsgHeader"]["Sequence"]
        with _lock:
            _accepted_batches += 1
            _accepted_total += len(events)
            for ev in events:
                _protocol_counts[ev["L7Protocol"]] += 1
                if len(_events) >= MAX_STORED_EVENTS:
                    _events.popleft()
                    _dropped_stored += 1
                _events.append(ev)
        self._json(200, {"accepted": len(events), "batch_sequence": sequence,
                         "schema": SCHEMA_VERSION})

    def _reject(self, status, error):
        global _rejected_total, _last_rejection
        with _lock:
            _rejected_total += 1
            _last_rejection = {"time": time.time(), "status": status, "error": error}
        self._json(status, {"error": error, "schema": SCHEMA_VERSION})

    # ── GET routes ──────────────────────────────────────────────────────────
    def do_GET(self):
        global _accepted_total, _accepted_batches, _rejected_total
        global _last_rejection, _dropped_stored
        parsed = urlparse(self.path)
        if parsed.path == "/events":
            rid = parse_qs(parsed.query).get("rid", [None])[0]
            with _lock:
                if rid is None:
                    snapshot = list(_events)
                else:
                    # Match the serialized event so the rid covers every field
                    # the event carries (HTTPReq.Query, HTTPReq.Uri, headers...).
                    snapshot = [ev for ev in _events
                                if rid in json.dumps(ev, sort_keys=True)]
            self._json(200, {"events": snapshot, "total": len(snapshot), "rid": rid})
        elif parsed.path == "/counts":
            with _lock:
                self._json(200, dict(_protocol_counts))
        elif parsed.path == "/summary":
            with _lock:
                self._json(200, {
                    "schema": SCHEMA_VERSION,
                    "accepted_total": _accepted_total,
                    "accepted_batches": _accepted_batches,
                    "rejected_total": _rejected_total,
                    "last_rejection": _last_rejection,
                    "dropped_store_overflow": _dropped_stored,
                    "stored": len(_events),
                    "by_protocol": dict(_protocol_counts),
                })
        elif parsed.path == "/reset":
            with _lock:
                _events.clear()
                _protocol_counts.clear()
                _accepted_total = 0
                _accepted_batches = 0
                _rejected_total = 0
                _last_rejection = None
                _dropped_stored = 0
            self._json(200, {"reset": True})
        elif parsed.path == "/health":
            self._json(200, {"status": "ok", "schema": SCHEMA_VERSION})
        else:
            self._json(404, {"error": "not found"})

    # ── helpers ─────────────────────────────────────────────────────────────
    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    server = ThreadedHTTPServer(("0.0.0.0", PORT), ValidatorHandler)
    print(f"Ingest validator on http://0.0.0.0:{PORT} (schema {SCHEMA_VERSION})")
    print("  POST /ingest          — receive MsgHeader/Batch envelopes (gzip OK)")
    print("  GET  /events[?rid=..] — retrieve captured events")
    print("  GET  /counts          — accepted event counts by L7Protocol")
    print("  GET  /summary         — accepted/rejected totals and last rejection")
    print("  GET  /reset           — clear all state")
    server.serve_forever()


if __name__ == "__main__":
    main()

