"""
Service-B (Receiver) — Port 8001
Verifies HMAC-SHA256 signatures on incoming requests.
Rejects anything with invalid/missing/expired signatures.
"""

import hmac
import hashlib
import base64
import time
import json
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException

app = FastAPI(title="Service-B (Receiver)")

# Shared secret — must match Service-A
SECRET_KEY = "my-super-secret-key-change-in-production-2024"

# Max request age: 5 minutes (prevents replay attacks)
MAX_AGE_MS = 300_000


def verify_signature(body: str, signature: str, timestamp: str) -> bool:
    """
    Verify HMAC-SHA256 signature.

    1. Check timestamp is within 5 minutes (anti-replay)
    2. Recalculate HMAC with same secret + timestamp + body
    3. Compare using hmac.compare_digest (constant-time, anti-timing-attack)
    """
    # Check timestamp freshness
    try:
        request_time = int(timestamp)
        now = int(time.time() * 1000)
        age = abs(now - request_time)
        if age > MAX_AGE_MS:
            print(f"  REJECTED: Request too old ({age}ms > {MAX_AGE_MS}ms)")
            return False
    except ValueError:
        print("  REJECTED: Invalid timestamp")
        return False

    # Recalculate expected signature
    data_to_sign = f"{timestamp}.{body}"
    expected = base64.b64encode(
        hmac.new(
            SECRET_KEY.encode(),
            data_to_sign.encode(),
            hashlib.sha256
        ).digest()
    ).decode()

    # Constant-time comparison (prevents timing attacks)
    valid = hmac.compare_digest(signature, expected)

    if not valid:
        print(f"  REJECTED: Signature mismatch")
        print(f"    Expected: {expected[:30]}...")
        print(f"    Received: {signature[:30]}...")

    return valid


@app.middleware("http")
async def hmac_auth_middleware(request: Request, call_next):
    """Middleware that verifies HMAC on all /api/ endpoints (except health)."""

    if not request.url.path.startswith("/api/") or request.url.path == "/api/health":
        return await call_next(request)

    # Extract headers
    signature = request.headers.get("X-HMAC-Signature")
    timestamp = request.headers.get("X-Timestamp")

    # Read body
    body = (await request.body()).decode()

    print("━" * 50)
    print(f"HMAC Verification: {request.method} {request.url.path}")
    print(f"  Timestamp: {timestamp}")
    print(f"  Signature: {signature[:20]}..." if signature else "  Signature: MISSING")
    print(f"  Body: {body[:80]}...")

    # Verify
    if not signature or not timestamp or not verify_signature(body, signature, timestamp):
        print("  Result: REJECTED")
        print("━" * 50)
        raise HTTPException(
            status_code=401,
            detail={"error": "HMAC verification failed", "message": "Invalid or missing signature"}
        )

    print("  Result: VERIFIED ✓")
    print("━" * 50)
    return await call_next(request)


@app.post("/api/receive")
async def receive(request: Request):
    """Process an HMAC-verified message from Service-A."""
    body = await request.body()
    payload = json.loads(body)

    print(f"Service-B received verified message: {payload}")

    return {
        "from": "service-b",
        "status": "received and verified",
        "received_payload": payload,
        "processed_at": datetime.now().isoformat(),
        "hmac_status": "VALID — message is authentic and untampered",
    }


@app.get("/api/health")
def health():
    return {"service": "service-b", "status": "UP", "port": 8001}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
