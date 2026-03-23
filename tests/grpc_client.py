#!/usr/bin/env python3
"""gRPC test client for protocol verification — uses health check + reflection."""
import sys
import ssl as _ssl

try:
    import grpc
    from grpc_health.v1 import health_pb2, health_pb2_grpc
    from grpc_reflection.v1alpha.proto_reflection_descriptor_database import ProtoReflectionDescriptorDatabase
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
                           "grpcio", "grpcio-reflection", "grpcio-health-checking"])
    import grpc
    from grpc_health.v1 import health_pb2, health_pb2_grpc
    from grpc_reflection.v1alpha.proto_reflection_descriptor_database import ProtoReflectionDescriptorDatabase


def test():
    host = sys.argv[1] if len(sys.argv) > 1 else "grpc-server"
    port = 50051
    target = f"{host}:{port}"
    print(f"Connecting to grpcs://{target}...")

    # Fetch the server's self-signed cert so we can trust it
    try:
        server_cert = _ssl.get_server_certificate((host, port))
        print(f"  Fetched server cert ({len(server_cert)} bytes)")
        creds = grpc.ssl_channel_credentials(
            root_certificates=server_cert.encode()
        )
    except Exception as e:
        print(f"  Cert fetch failed ({e}), trying without verification...")
        creds = grpc.ssl_channel_credentials()

    channel = grpc.secure_channel(target, creds)

    try:
        # Health check — generates content-type: application/grpc traffic
        health_stub = health_pb2_grpc.HealthStub(channel)
        resp = health_stub.Check(health_pb2.HealthCheckRequest(service=""))
        print(f"  Health check: {health_pb2.HealthCheckResponse.ServingStatus.Name(resp.status)}")

        resp = health_stub.Check(health_pb2.HealthCheckRequest(service="sentinel.test.TradeService"))
        print(f"  TradeService health: {health_pb2.HealthCheckResponse.ServingStatus.Name(resp.status)}")

        # Reflection — discover registered services
        db = ProtoReflectionDescriptorDatabase(channel)
        services = db.get_services()
        print(f"  gRPC services discovered: {services}")

        print("gRPC test PASSED")
    except Exception as e:
        print(f"  gRPC error: {e}")
    finally:
        channel.close()


if __name__ == "__main__":
    test()
