#!/usr/bin/env python3
"""WebSocket test client for protocol verification."""
import asyncio
import ssl
import sys

try:
    import websockets
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "websockets"])
    import websockets


async def test():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    host = sys.argv[1] if len(sys.argv) > 1 else "ws-server"
    uri = f"wss://{host}:8445"
    print(f"Connecting to {uri}...")

    async with websockets.connect(uri, ssl=ctx) as ws:
        await ws.send('{"type":"ping"}')
        resp = await ws.recv()
        print(f"WS response 1: {resp}")

        await ws.send('{"type":"subscribe","channel":"trades"}')
        resp = await ws.recv()
        print(f"WS response 2: {resp}")

    print("WebSocket test PASSED")


if __name__ == "__main__":
    asyncio.run(test())
