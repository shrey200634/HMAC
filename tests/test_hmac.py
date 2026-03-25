"""
Unit tests for HMAC Inter-Service Authentication.

Tests cover:
  1. Signature generation (Service A)
  2. Signature verification (Service B)
  3. Anti-replay (expired timestamp)
  4. Anti-tampering (modified body)
  5. Missing signature / timestamp
  6. Health endpoints
  7. Full integration: A → B flow
"""

import base64
import hashlib
import hmac
import os
import sys
import time

from fastapi.testclient import TestClient

# Set env vars BEFORE importing the apps
os.environ["HMAC_SECRET_KEY"] = "test-secret-key-for-unit-tests"
os.environ["SERVICE_B_URL"] = "http://localhost:8001"
os.environ["HMAC_MAX_AGE_MS"] = "300000"

# Add service directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "serviceA"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "serviceB"))

from serviceA.main import app as app_a
from serviceA.main import generate_signature
from serviceB.main import app as app_b
from serviceB.main import verify_signature

client_a = TestClient(app_a, raise_server_exceptions=False)
client_b = TestClient(app_b, raise_server_exceptions=False)

SECRET = "test-secret-key-for-unit-tests"


# ═══════════════════════════════════════════
# TEST 1: Signature Generation
# ═══════════════════════════════════════════


class TestSignatureGeneration:
    """Test that Service A generates valid HMAC-SHA256 signatures."""

    def test_generates_base64_signature(self):
        """Signature should be a valid base64 string."""
        sig = generate_signature('{"msg":"hello"}', "1234567890000")
        # Should not raise — valid base64
        decoded = base64.b64decode(sig)
        assert len(decoded) == 32  # SHA256 = 32 bytes

    def test_same_input_same_signature(self):
        """Same body + timestamp should always produce the same signature."""
        body = '{"orderId":42}'
        ts = "1700000000000"
        sig1 = generate_signature(body, ts)
        sig2 = generate_signature(body, ts)
        assert sig1 == sig2

    def test_different_body_different_signature(self):
        """Different body should produce a different signature."""
        ts = "1700000000000"
        sig1 = generate_signature('{"a":1}', ts)
        sig2 = generate_signature('{"a":2}', ts)
        assert sig1 != sig2

    def test_different_timestamp_different_signature(self):
        """Different timestamp should produce a different signature."""
        body = '{"a":1}'
        sig1 = generate_signature(body, "1000")
        sig2 = generate_signature(body, "2000")
        assert sig1 != sig2


# ═══════════════════════════════════════════
# TEST 2: Signature Verification
# ═══════════════════════════════════════════


class TestSignatureVerification:
    """Test that Service B correctly verifies signatures."""

    def _make_valid_signature(self, body: str, timestamp: str) -> str:
        """Helper: create a valid HMAC signature."""
        data = f"{timestamp}.{body}"
        sig = hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).digest()
        return base64.b64encode(sig).decode()

    def test_valid_signature_passes(self):
        """A correctly signed request should pass verification."""
        body = '{"message":"hello"}'
        ts = str(int(time.time() * 1000))
        sig = self._make_valid_signature(body, ts)
        assert verify_signature(body, sig, ts) is True

    def test_wrong_signature_fails(self):
        """A fake signature should be rejected."""
        body = '{"message":"hello"}'
        ts = str(int(time.time() * 1000))
        assert verify_signature(body, "fakesignature", ts) is False

    def test_tampered_body_fails(self):
        """If body is modified after signing, verification should fail."""
        original_body = '{"amount":100}'
        ts = str(int(time.time() * 1000))
        sig = self._make_valid_signature(original_body, ts)
        tampered_body = '{"amount":999}'  # attacker changes amount
        assert verify_signature(tampered_body, sig, ts) is False

    def test_expired_timestamp_fails(self):
        """A request older than 5 minutes should be rejected (anti-replay)."""
        body = '{"message":"old"}'
        old_ts = str(int(time.time() * 1000) - 400_000)  # 6.6 min ago
        sig = self._make_valid_signature(body, old_ts)
        assert verify_signature(body, sig, old_ts) is False

    def test_fresh_timestamp_passes(self):
        """A request from 1 second ago should pass."""
        body = '{"message":"fresh"}'
        ts = str(int(time.time() * 1000) - 1000)  # 1 second ago
        sig = self._make_valid_signature(body, ts)
        assert verify_signature(body, sig, ts) is True

    def test_invalid_timestamp_format_fails(self):
        """Non-numeric timestamp should be rejected."""
        body = '{"message":"bad"}'
        assert verify_signature(body, "somesig", "not-a-number") is False


# ═══════════════════════════════════════════
# TEST 3: Service A Health Endpoint
# ═══════════════════════════════════════════


class TestServiceAHealth:
    def test_health_returns_200(self):
        resp = client_a.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "service-a"
        assert data["status"] == "UP"


# ═══════════════════════════════════════════
# TEST 4: Service B Health Endpoint
# ═══════════════════════════════════════════


class TestServiceBHealth:
    def test_health_returns_200(self):
        resp = client_b.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "service-b"
        assert data["status"] == "UP"


# ═══════════════════════════════════════════
# TEST 5: Service B — Reject Invalid Requests
# ═══════════════════════════════════════════


class TestServiceBRejectsInvalid:
    """Test that Service B rejects all forms of invalid requests."""

    def test_no_signature_returns_401(self):
        """Request with no HMAC headers should be rejected."""
        resp = client_b.post(
            "/api/receive",
            json={"message": "no auth"},
        )
        assert resp.status_code == 401

    def test_fake_signature_returns_401(self):
        """Request with fake signature should be rejected."""
        resp = client_b.post(
            "/api/receive",
            content='{"message":"impersonator"}',
            headers={
                "Content-Type": "application/json",
                "X-HMAC-Signature": "totally-fake-signature",
                "X-Timestamp": str(int(time.time() * 1000)),
            },
        )
        assert resp.status_code == 401

    def test_missing_timestamp_returns_401(self):
        """Request with signature but no timestamp should be rejected."""
        resp = client_b.post(
            "/api/receive",
            content='{"message":"no timestamp"}',
            headers={
                "Content-Type": "application/json",
                "X-HMAC-Signature": "somesig",
            },
        )
        assert resp.status_code == 401

    def test_expired_request_returns_401(self):
        """Request from 10 minutes ago should be rejected (anti-replay)."""
        body = '{"message":"old request"}'
        old_ts = str(int(time.time() * 1000) - 600_000)  # 10 min ago
        data = f"{old_ts}.{body}"
        sig = base64.b64encode(hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).digest()).decode()

        resp = client_b.post(
            "/api/receive",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-HMAC-Signature": sig,
                "X-Timestamp": old_ts,
            },
        )
        assert resp.status_code == 401


# ═══════════════════════════════════════════
# TEST 6: Service B — Accept Valid Request
# ═══════════════════════════════════════════


class TestServiceBAcceptsValid:
    """Test that Service B accepts properly signed requests."""

    def test_valid_signed_request_returns_200(self):
        """A correctly signed, fresh request should be accepted."""
        body = '{"message":"legit","orderId":42}'
        ts = str(int(time.time() * 1000))
        data = f"{ts}.{body}"
        sig = base64.b64encode(hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).digest()).decode()

        resp = client_b.post(
            "/api/receive",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-HMAC-Signature": sig,
                "X-Timestamp": ts,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["hmac_status"] == "VALID — message is authentic and untampered"
        assert data["received_payload"]["orderId"] == 42
