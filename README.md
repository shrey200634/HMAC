# HMAC Inter-Service Authentication Demo (FastAPI)

Two FastAPI services that communicate using HMAC-SHA256 message authentication.

## How to Run

```bash
pip install -r requirements.txt
```

Terminal 1 — start Service-B (receiver):
```bash
cd service-b
python main.py
```

Terminal 2 — start Service-A (sender):
```bash
cd service-a
python main.py
```

## Test

### Valid request (through Service-A):
```bash
curl -X POST http://localhost:8000/api/send -H "Content-Type: application/json" -d '{"message":"Hello","orderId":42}'
```

### Tampered request (direct to Service-B, wrong signature):
```bash
curl -X POST http://localhost:8001/api/receive -H "Content-Type: application/json" -H "X-HMAC-Signature: fake" -H "X-Timestamp: 1234567890000" -d '{"message":"impersonator"}'
```
→ Returns **401 Unauthorized**

### No signature at all:
```bash
curl -X POST http://localhost:8001/api/receive -H "Content-Type: application/json" -d '{"message":"no auth"}'
```
→ Returns **401 Unauthorized**

## How HMAC Works

```
Service-A                                    Service-B
─────────                                    ─────────
1. body = JSON payload                       
2. timestamp = current epoch ms              
3. signature = HMAC-SHA256(                  
     timestamp + "." + body,                 
     shared_secret                           
   )                                         
4. Send POST with headers:                  
   X-HMAC-Signature: <signature>            
   X-Timestamp: <timestamp>                 
   Body: <json>                             
                            ───────>         1. Extract signature + timestamp
                                             2. Check timestamp < 5 min old
                                             3. Recalculate HMAC with same
                                                secret + timestamp + body
                                             4. Compare (constant-time)
                                             5. Match → 200 / Mismatch → 401
```

## Security Features

- **Anti-replay**: Requests older than 5 minutes are rejected
- **Anti-timing-attack**: Uses `hmac.compare_digest()` (constant-time comparison)
- **Anti-tampering**: Any change to body invalidates the signature
- **Anti-impersonation**: Only holders of the shared secret can sign
