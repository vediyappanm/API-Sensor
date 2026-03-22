#!/usr/bin/env python3
"""Minimal gRPC test server with TLS for sensor integration testing."""
import subprocess
import sys
import os
import tempfile
import time
from concurrent import futures

# Install grpcio at runtime if not present
try:
    import grpc
    from grpc_reflection.v1alpha import reflection
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "grpcio", "grpcio-tools", "grpcio-reflection"])
    import grpc
    from grpc_reflection.v1alpha import reflection

# Inline proto definition — avoids needing .proto files
PROTO_CONTENT = """
syntax = "proto3";

package sentinel.test;

service TradeService {
    rpc GetTrade (TradeRequest) returns (TradeResponse);
    rpc GetQuote (QuoteRequest) returns (QuoteResponse);
}

message TradeRequest { string trade_id = 1; }
message TradeResponse {
    string trade_id = 1;
    string symbol = 2;
    double price = 3;
    string status = 4;
}
message QuoteRequest { string symbol = 1; }
message QuoteResponse {
    string symbol = 1;
    double bid = 2;
    double ask = 3;
    int64 timestamp = 4;
}
"""

# Write proto, compile it
proto_dir = tempfile.mkdtemp()
proto_file = os.path.join(proto_dir, "trade.proto")
with open(proto_file, "w") as f:
    f.write(PROTO_CONTENT)

subprocess.run([
    sys.executable, "-m", "grpc_tools.protoc",
    f"--proto_path={proto_dir}",
    f"--python_out={proto_dir}",
    f"--grpc_python_out={proto_dir}",
    proto_file,
], check=True)

sys.path.insert(0, proto_dir)
import trade_pb2
import trade_pb2_grpc


class TradeServicer(trade_pb2_grpc.TradeServiceServicer):
    def GetTrade(self, request, context):
        return trade_pb2.TradeResponse(
            trade_id=request.trade_id,
            symbol="NIFTY50",
            price=22450.75,
            status="FILLED",
        )

    def GetQuote(self, request, context):
        return trade_pb2.QuoteResponse(
            symbol=request.symbol,
            bid=22448.50,
            ask=22451.00,
            timestamp=int(time.time()),
        )


def make_self_signed_cert():
    cert_file = tempfile.NamedTemporaryFile(suffix=".crt", delete=False)
    key_file  = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
    cert_file.close()
    key_file.close()
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file.name, "-out", cert_file.name,
        "-days", "1", "-nodes", "-subj", "/CN=grpc-server",
        "-addext", "subjectAltName=DNS:grpc-server,DNS:localhost,IP:127.0.0.1"
    ], check=True, capture_output=True)
    with open(cert_file.name, "rb") as f:
        cert = f.read()
    with open(key_file.name, "rb") as f:
        key = f.read()
    return key, cert


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    trade_pb2_grpc.add_TradeServiceServicer_to_server(TradeServicer(), server)

    # Enable reflection for grpcurl discovery
    SERVICE_NAMES = (
        trade_pb2.DESCRIPTOR.services_by_name["TradeService"].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(SERVICE_NAMES, server)

    key, cert = make_self_signed_cert()
    creds = grpc.ssl_server_credentials([(key, cert)])
    server.add_secure_port("[::]:50051", creds)

    print("gRPC TLS server on grpcs://0.0.0.0:50051")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
