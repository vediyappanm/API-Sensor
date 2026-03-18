import requests
import time
import json
import uuid
import sys
import os

# Add project root to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from server.modules.auth.jwt_issuer import JWTIssuer

# Configuration
INGEST_URL = "http://localhost:8000/api/ingestion/v2/events"
ACCOUNT_ID = 1000000

def get_auth_token():
    """Generates a valid JWT token for the demo account."""
    return JWTIssuer.create_access_token({
        "user_id": "sensor-test-user",
        "account_id": ACCOUNT_ID,
        "role": "ADMIN",
    })

def simulate_sensor_event():
    """Builds a sample event batch similar to what the Rust sensor produces."""
    event = {
        "version": "v1",
        "event_type": "api_traffic",
        "source": "ebpf-mock",
        "account_id": ACCOUNT_ID,
        "observed_at": int(time.time() * 1000),
        "protocol": "HTTP/1.1",
        "request": {
            "method": "POST",
            "path": "/api/v1/login",
            "host": "example.com",
            "scheme": "https",
            "headers": {
                "host": "example.com",
                "user-agent": "Mozilla/5.0",
                "content-type": "application/json"
            },
            "query": {},
            "body": None
        },
        "response": {
            "status_code": 200,
            "headers": {
                "content-type": "application/json",
                "server": "nginx"
            },
            "body": None,
            "latency_ms": 45
        },
        "collection_id": None,
        "source_ip": "192.168.1.10"
    }
    
    batch = {
        "version": "v1",
        "events": [event]
    }
    return batch

def test_ingestion():
    batch = simulate_sensor_event()
    token = get_auth_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print(f"Sending batch with {len(batch['events'])} events to {INGEST_URL}...")
    try:
        resp = requests.post(INGEST_URL, json=batch, headers=headers)
        print(f"Response Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            job_id = data.get("job_id")
            print(f"SUCCESS: Job ID created: {job_id}")
            print(f"Accepted events: {data.get('accepted')}")
            return True
        else:
            print(f"FAILED: Ingestion rejected. Body: {resp.text}")
            return False
    except requests.exceptions.ConnectionError:
        print("ERROR: Could not connect to the server at localhost:8000.")
        print("Tip: Start the server first with: python -m uvicorn server.api.main:app --reload")
        return False

if __name__ == "__main__":
    test_ingestion()
