#!/usr/bin/env python3
"""gRPC test client for protocol verification."""
import sys
import ssl as _ssl

try:
    import grpc
    from grpc_reflection.v1alpha.proto_reflection_descriptor_database import ProtoReflectionDescriptorDatabase
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "grpcio", "grpcio-reflection"])
    import grpc
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
        db = ProtoReflectionDescriptorDatabase(channel)
        services = db.get_services()
        print(f"  gRPC services discovered: {services}")
        print("gRPC test PASSED")
    except Exception as e:
        print(f"  gRPC reflection error: {e}")
    finally:
        channel.close()


if __name__ == "__main__":
    test()
