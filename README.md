# HMAC Inter-Service Authentication Demo (FastAPI)

Two FastAPI microservices communicating using HMAC-SHA256 message authentication — Dockerized with unit tests and pre-commit linting.

## Quick Start (Docker Compose)

```bash
# 1. Clone and configure
cp .env.example .env    # edit with your secret key

# 2. Run both services
docker-compose up -d --build

# 3. Test
curl -X POST http://localhost:8000/api/send \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello","orderId":42}'
```

## Architecture

```
Service-A (Sender) :8000              Service-B (Receiver) :8001
─────────────────────────              ─────────────────────────
1. Receives client request             1. Extracts signature + timestamp
2. Serializes payload to JSON          2. Checks timestamp < 5 min old
3. Generates HMAC-SHA256 signature     3. Recalculates HMAC with same
   using shared secret + timestamp        secret + timestamp + body
4. Sends to Service-B with headers:    4. Constant-time comparison
   X-HMAC-Signature + X-Timestamp      5. Match → 200 / Mismatch → 401
```

## Test Endpoints

```bash
# Valid request (through Service A → Service B)
curl -X POST http://localhost:8000/api/send \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello","orderId":42}'

# Tampered request (direct to Service B — rejected)
curl -X POST http://localhost:8001/api/receive \
  -H "Content-Type: application/json" \
  -H "X-HMAC-Signature: fake" \
  -H "X-Timestamp: 1234567890000" \
  -d '{"message":"impersonator"}'
# → 401 Unauthorized

# No signature at all
curl -X POST http://localhost:8001/api/receive \
  -H "Content-Type: application/json" \
  -d '{"message":"no auth"}'
# → 401 Unauthorized

# Health checks
curl http://localhost:8000/api/health
curl http://localhost:8001/api/health
```

## Run Unit Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Pre-Commit Hook Setup

```bash
pip install pre-commit
pre-commit install
# Now every git commit will auto-lint with ruff
```

## Security Features

- **Anti-replay**: Requests older than 5 minutes are rejected
- **Anti-timing-attack**: Uses `hmac.compare_digest()` (constant-time comparison)
- **Anti-tampering**: Any change to body invalidates the signature
- **Anti-impersonation**: Only holders of the shared secret can sign
- **No hardcoded secrets**: All config via environment variables / `.env`

## Project Structure

```
HMAC/
├── docker-compose.yml          # Orchestrates both services
├── .env.example                # Template for environment variables
├── .env                        # Actual secrets (git-ignored)
├── .pre-commit-config.yaml     # Ruff linter on every commit
├── .gitignore
├── pyproject.toml              # Ruff config
├── requirements.txt            # All dependencies
├── serviceA/
│   ├── Dockerfile
│   ├── main.py                 # Sender — signs requests
│   └── requirements.txt
├── serviceB/
│   ├── Dockerfile
│   ├── main.py                 # Receiver — verifies signatures
│   └── requirements.txt
└── tests/
    └── test_hmac.py            # 16 unit tests
```

## Docker Commands

```bash
docker-compose up -d --build     # Start both services
docker-compose ps                # Check status
docker-compose logs service-a    # View Service A logs
docker-compose logs service-b    # View Service B logs
docker-compose down              # Stop everything
```
