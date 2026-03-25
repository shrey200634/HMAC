"""
Service-A (Sender) — Port 8000
Signs outgoing requests with HMAC-SHA256 before sending to Service-B.
"""

import base64
import hashlib
import hmac
import json
import os
import time

import httpx
from fastapi import FastAPI

app = FastAPI(title="Service-A (Sender)")

# Read from environment variables — NO hardcoded secrets
SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", "default-dev-key")
SERVICE_B_URL = os.environ.get("SERVICE_B_URL", "http://localhost:8001")


def generate_signature(body: str, timestamp: str) -> str:
    """
    Generate HMAC-SHA256 signature.

    1. Combine timestamp + body to prevent replay attacks
    2. Hash with shared secret using HMAC-SHA256
    3. Base64 encode for safe HTTP header transport
    """
    data_to_sign = f"{timestamp}.{body}"
    signature = hmac.new(SECRET_KEY.encode(), data_to_sign.encode(), hashlib.sha256).digest()
    return base64.b64encode(signature).decode()


@app.post("/api/send")
async def send_to_service_b(payload: dict):
    """Send an HMAC-signed request to Service-B."""

    # Step 1: Serialize payload
    body = json.dumps(payload, separators=(",", ":"))

    # Step 2: Get current timestamp
    timestamp = str(int(time.time() * 1000))

    # Step 3: Generate HMAC signature
    signature = generate_signature(body, timestamp)

    # Step 4: Send with HMAC headers
    headers = {
        "Content-Type": "application/json",
        "X-HMAC-Signature": signature,
        "X-Timestamp": timestamp,
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{SERVICE_B_URL}/api/receive",
                content=body,
                headers=headers,
            )
            return {
                "from": "service-a",
                "sent_to": "service-b",
                "service_b_status": resp.status_code,
                "service_b_response": resp.json(),
            }
        except httpx.ConnectError:
            return {"error": "Cannot reach Service-B. Is it running on port 8001?"}


@app.get("/api/health")
def health():
    return {"service": "service-a", "status": "UP", "port": 8000}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
