#!/usr/bin/env python3
"""WebSocket test server over TLS — for sensor integration testing."""
import asyncio
import json
import ssl
import os
import tempfile
from datetime import datetime, timedelta

try:
    import websockets
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets"])
    import websockets

async def handler(websocket):
    print(f"WS connection from {websocket.remote_address}")
    try:
        async for message in websocket:
            try:
                data = json.loads(message)
                msg_type = data.get("type", "echo")
                if msg_type == "ping":
                    await websocket.send(json.dumps({"type": "pong", "ts": datetime.utcnow().isoformat()}))
                elif msg_type == "message":
                    await websocket.send(json.dumps({
                        "type": "ack",
                        "content": data.get("content", ""),
                        "ts": datetime.utcnow().isoformat(),
                    }))
                else:
                    await websocket.send(json.dumps({"type": "echo", "data": data}))
            except json.JSONDecodeError:
                await websocket.send(json.dumps({"type": "error", "msg": "invalid json"}))
    except websockets.exceptions.ConnectionClosed:
        pass

def make_self_signed_cert():
    """Generate a self-signed cert for testing using openssl CLI."""
    cert_file = tempfile.NamedTemporaryFile(suffix=".crt", delete=False)
    key_file  = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
    cert_file.close()
    key_file.close()
    os.system(
        f"openssl req -x509 -newkey rsa:2048 -keyout {key_file.name} "
        f"-out {cert_file.name} -days 1 -nodes -subj '/CN=localhost' 2>/dev/null"
    )
    return cert_file.name, key_file.name

async def main():
    cert_path, key_path = make_self_signed_cert()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(cert_path, key_path)

    async with websockets.serve(handler, "0.0.0.0", 8445, ssl=ssl_ctx):
        print("WebSocket TLS server on wss://0.0.0.0:8445")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
