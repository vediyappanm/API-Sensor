#!/usr/bin/env python3
"""Regression tests for the ingest validator (audit F20).

These tests pin the validator to the REAL production wire contract:
MsgHeader/Batch envelope, flat dotted-key events, gzip payloads, and the
rid-correlation query. They also prove the validator rejects the legacy nested
`{"events": [...]}` schema, empty batches, and malformed envelopes — so a
schema regression can never silently pass with zero accepted events.

Run:  python -m unittest discover -s tests/test-servers/validator -v
"""
import gzip
import http.client
import json
import os
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_PY = os.path.join(HERE, "server.py")

# The subprocess server runs with deliberately small caps so boundary behaviour
# is testable with modest payloads.
PORT = 19877
MAX_BODY_BYTES = 65536
MAX_DECOMPRESSED_BYTES = 262144
MAX_STORED = 50

_server = None


def _wait_healthy(timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=1)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            if resp.status == 200 and b"sensor-batch" in body:
                return True
        except OSError:
            time.sleep(0.1)
    return False


def setUpModule():
    global _server
    env = dict(os.environ)
    env.update({
        "VALIDATOR_PORT": str(PORT),
        "VALIDATOR_MAX_BODY_BYTES": str(MAX_BODY_BYTES),
        "VALIDATOR_MAX_DECOMPRESSED_BYTES": str(MAX_DECOMPRESSED_BYTES),
        "VALIDATOR_MAX_STORED": str(MAX_STORED),
    })
    _server = subprocess.Popen([sys.executable, SERVER_PY], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_healthy():
        tearDownModule()
        raise RuntimeError("validator server failed to start")


def tearDownModule():
    global _server
    if _server is not None:
        _server.terminate()
        try:
            _server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _server.kill()
        _server = None


def request(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else None)
    finally:
        conn.close()


def make_event(rid="rid-default", proto="HTTP11", method="GET",
               uri="/api/users", query="rid=rid-default"):
    """A production-shaped flat dotted-key event (userspace/src/output.rs)."""
    return {
        "SrcInfo.Source": 2,
        "SrcInfo.RemoteAddress": "10.0.0.5",
        "LogVersion": "v4",
        "Id": f"deadbeef-0000000000000001{0:04x}",
        "SessionStats.StartTime": "2026-10-13 12:00:00.000",
        "SessionStats.TimeToLastDownstreamTxByte": 12,
        "DownstreamL3L4.SourceIP": "10.0.0.5",
        "DownstreamL3L4.DestIP": "10.0.0.9",
        "DownstreamL3L4.L4Protocol": "L4Proto_TCP",
        "DownstreamL3L4.SourcePort": 40000,
        "DownstreamL3L4.DestPort": 443,
        "UpstreamL3L4.SourceIP": "",
        "UpstreamL3L4.DestIP": "10.0.0.9",
        "UpstreamL3L4.L4Protocol": "L4Proto_Unknown",
        "UpstreamL3L4.SourcePort": 0,
        "UpstreamL3L4.DestPort": 443,
        "L7Protocol": proto,
        "HTTPReq.Method": method,
        "HTTPReq.Uri": uri,
        "HTTPReq.Query": query,
        "HTTPReq.BodyLength": 0,
        "HTTPReq.Body": None,
        "HTTPReq.PathParams": "{}",
        "Req.Header.user-agent": "unit-test",
        "Req.Header.host": "localhost",
        "HTTPResp.BodyLength": 2,
        "HTTPResp.Body": None,
        "HTTPResp.ResponseCode": 200,
        "HTTPResp.ResponseCodeDetails": "",
        "Resp.Header.content-length": 2,
        "Resp.Header.content-type": "application/json",
        "session_id": "sid-0",
        "auth_session_id": "0",
        "user_id": "unknown",
        "user_role": "unknown",
        "APIInfo.Name": "",
        "APIInfo.Id": 0,
        "OnPremAction.FinalActionLog": True,
        "MetaDataMap": {"namespace": "test"},
        "MetaDataOnly": False,
        "APIID": 12345,
        "error_flags": [],
        "Proto": "rest",
    }


def make_envelope(events, sequence=1, tenant="test-tenant"):
    return {
        "MsgHeader": {
            "Version": "2.0",
            "MessageTime": "2026-10-13 12:00:00.000",
            "TenantId": tenant,
            "Sequence": sequence,
            "InternalOPCID": "0123456789abcdef",
            "PolicyVersion": "1",
        },
        "Batch": events,
    }


def post_json(obj, headers=None, compress=False):
    body = json.dumps(obj).encode()
    hdrs = {"Content-Type": "application/json"}
    if compress:
        body = gzip.compress(body)
        hdrs["Content-Encoding"] = "gzip"
    if headers:
        hdrs.update(headers)
    return request("POST", "/ingest", body=body, headers=hdrs)


class ValidatorTestCase(unittest.TestCase):
    def setUp(self):
        status, body = request("GET", "/reset")
        self.assertEqual(status, 200, body)

    def summary(self):
        status, body = request("GET", "/summary")
        self.assertEqual(status, 200)
        return body


class TestValidEnvelope(ValidatorTestCase):
    def test_uncompressed_batch_accepted_and_stored(self):
        ev = make_event(rid="ok-1", query="rid=ok-1")
        status, body = post_json(make_envelope([ev], sequence=7))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["accepted"], 1)
        self.assertEqual(body["batch_sequence"], 7)

        status, events = request("GET", "/events")
        self.assertEqual(status, 200)
        self.assertEqual(events["total"], 1)
        self.assertEqual(events["events"][0]["HTTPReq.Method"], "GET")

        summary = self.summary()
        self.assertEqual(summary["accepted_total"], 1)
        self.assertEqual(summary["accepted_batches"], 1)
        self.assertEqual(summary["by_protocol"], {"HTTP11": 1})

    def test_gzip_batch_accepted(self):
        evs = [make_event(rid=f"gzip-{i}", query=f"rid=gzip-{i}") for i in range(3)]
        status, body = post_json(make_envelope(evs), compress=True)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["accepted"], 3)
        self.assertEqual(self.summary()["accepted_total"], 3)

    def test_gzip_magic_without_header_accepted(self):
        # The sensor sets Content-Encoding, but a proxy might strip it; the
        # gzip magic bytes alone must still route through decompression.
        ev = make_event(rid="magic-1", query="rid=magic-1")
        body = gzip.compress(json.dumps(make_envelope([ev])).encode())
        status, resp = request("POST", "/ingest", body=body,
                               headers={"Content-Type": "application/json"})
        self.assertEqual(status, 200, resp)
        self.assertEqual(resp["accepted"], 1)

    def test_multi_protocol_counts(self):
        evs = [make_event(proto="HTTP2", query="rid=h2"),
               make_event(proto="GRPC", query="rid=grpc"),
               make_event(proto="HTTP2", query="rid=h2b")]
        status, _ = post_json(make_envelope(evs))
        self.assertEqual(status, 200)
        status, counts = request("GET", "/counts")
        self.assertEqual(counts, {"HTTP2": 2, "GRPC": 1})


class TestLegacySchemaRejected(ValidatorTestCase):
    def test_legacy_nested_events_schema_rejected(self):
        legacy = {"version": "1.0", "events": [
            {"protocol": "HTTP/1.1",
             "request": {"method": "GET", "path": "/x", "headers": {}},
             "response": {"status_code": 200}}]}
        status, body = post_json(legacy)
        self.assertEqual(status, 400)
        self.assertIn("legacy", body["error"])
        summary = self.summary()
        self.assertEqual(summary["accepted_total"], 0,
                         "legacy schema must not be counted as accepted")
        self.assertEqual(summary["rejected_total"], 1)
        status, events = request("GET", "/events")
        self.assertEqual(events["total"], 0, "zero events must remain visible")

    def test_zero_event_batch_rejected(self):
        status, body = post_json(make_envelope([]))
        self.assertEqual(status, 400)
        self.assertIn("empty", body["error"])

class TestMalformedRejected(ValidatorTestCase):
    def test_missing_msgheader(self):
        status, body = post_json({"Batch": [make_event()]})
        self.assertEqual(status, 400)
        self.assertIn("MsgHeader", body["error"])

    def test_msgheader_missing_field(self):
        env = make_envelope([make_event()])
        del env["MsgHeader"]["Sequence"]
        status, body = post_json(env)
        self.assertEqual(status, 400)
        self.assertIn("Sequence", body["error"])

    def test_msgheader_wrong_type(self):
        env = make_envelope([make_event()])
        env["MsgHeader"]["Sequence"] = "1"  # must be int, not str
        status, _ = post_json(env)
        self.assertEqual(status, 400)

    def test_batch_not_a_list(self):
        env = make_envelope([make_event()])
        env["Batch"] = {"0": make_event()}
        status, _ = post_json(env)
        self.assertEqual(status, 400)

    def test_event_missing_required_key(self):
        ev = make_event()
        del ev["L7Protocol"]
        status, body = post_json(make_envelope([ev]))
        self.assertEqual(status, 400)
        self.assertIn("L7Protocol", body["error"])

    def test_event_wrong_type(self):
        ev = make_event()
        ev["HTTPReq.BodyLength"] = "12"  # must be int
        status, _ = post_json(make_envelope([ev]))
        self.assertEqual(status, 400)

    def test_event_bool_is_not_int(self):
        ev = make_event()
        ev["APIID"] = True  # Python bool is an int subclass; schema says no
        status, _ = post_json(make_envelope([ev]))
        self.assertEqual(status, 400)

    def test_unknown_l7_protocol_rejected(self):
        ev = make_event(proto="TLSv1.3")
        status, body = post_json(make_envelope([ev]))
        self.assertEqual(status, 400)
        self.assertIn("TLSv1.3", body["error"])

    def test_invalid_json_rejected(self):
        status, _ = request("POST", "/ingest", body=b"{not json",
                            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)

    def test_zero_content_length_rejected(self):
        status, _ = request("POST", "/ingest", body=b"",
                            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 400)

    def test_truncated_gzip_rejected(self):
        blob = gzip.compress(json.dumps(make_envelope([make_event()])).encode())
        status, body = request("POST", "/ingest", body=blob[:-5],
                               headers={"Content-Type": "application/json",
                                        "Content-Encoding": "gzip"})
        self.assertEqual(status, 400)
        self.assertIn("gzip", body["error"])

    def test_rejected_batch_stores_nothing(self):
        post_json({"events": []})  # rejected
        status, events = request("GET", "/events")
        self.assertEqual(events["total"], 0)
        summary = self.summary()
        self.assertEqual(summary["accepted_total"], 0)
        self.assertEqual(summary["rejected_total"], 1)
        self.assertEqual(summary["last_rejection"]["status"], 400)

class TestBounds(ValidatorTestCase):
    def test_oversized_body_rejected_with_413(self):
        ev = make_event()
        ev["Req.Header.user-agent"] = "A" * (MAX_BODY_BYTES + 1024)
        status, body = post_json(make_envelope([ev]))
        self.assertEqual(status, 413, body)

    def test_oversized_decompressed_payload_rejected(self):
        ev = make_event()
        ev["Req.Header.cookie"] = "B" * (MAX_DECOMPRESSED_BYTES + 1024)
        status, _ = post_json(make_envelope([ev]), compress=True)
        self.assertEqual(status, 400)

    def test_store_overflow_is_bounded_and_visible(self):
        n = MAX_STORED + 10
        half = n // 2
        evs_a = [make_event(rid=f"ovf-{i}", query=f"rid=ovf-{i}") for i in range(half)]
        evs_b = [make_event(rid=f"ovf-{i}", query=f"rid=ovf-{i}")
                 for i in range(half, n)]
        self.assertEqual(post_json(make_envelope(evs_a))[0], 200)
        self.assertEqual(post_json(make_envelope(evs_b, sequence=2))[0], 200)
        summary = self.summary()
        self.assertEqual(summary["accepted_total"], n)
        self.assertEqual(summary["stored"], MAX_STORED)
        self.assertEqual(summary["dropped_store_overflow"], n - MAX_STORED)


class TestRidOracle(ValidatorTestCase):
    def test_rid_filter_returns_only_matching_events(self):
        evs = [make_event(rid="alpha-1", query="rid=alpha-1&x=1"),
               make_event(rid="beta-2", query="rid=beta-2&x=2"),
               make_event(proto="HTTP2", rid="alpha-2", query="rid=alpha-2")]
        self.assertEqual(post_json(make_envelope(evs))[0], 200)

        status, body = request("GET", "/events?rid=alpha-1")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["events"][0]["HTTPReq.Query"], "rid=alpha-1&x=1")

        status, body = request("GET", "/events?rid=alpha")
        self.assertEqual(body["total"], 2, "rid is a substring filter")

        status, body = request("GET", "/events?rid=nothing-matches")
        self.assertEqual(body["total"], 0)

        status, body = request("GET", "/events")
        self.assertEqual(body["total"], 3)

    def test_unknown_path_404(self):
        status, _ = request("GET", "/nope")
        self.assertEqual(status, 404)
        status, _ = request("POST", "/wrong", body=b"{}",
                            headers={"Content-Type": "application/json"})
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()



