# setsig-python

Official Python SDK for [setsig.com](https://setsig.com) — Physical Presence & Verification Infrastructure-as-a-Service (PaaS/IaaS).

[![PyPI version](https://badge.fury.io/py/setsig.svg)](https://badge.fury.io/py/setsig)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Zero external dependencies! Built natively using the Python standard library (`urllib.request`, `hmac`, `hashlib`, `dataclasses`).

---

## Installation

```bash
pip install setsig
```

Requirements: Python 3.10 or newer.

---

## Quickstart

### 1. Initialize Client

```python
from setsig import Setsig, TokenFormat

client = Setsig(
    api_key="sk_live_...",
    timeout=10.0,
    max_retries=3,
)

# Generate a dynamic presence QR token for your venue
token = client.tokens.generate(
    venue_id="ven_ist_headquarters",
    ttl=60,
    format=TokenFormat.SVG,
    idempotency_key="idemp_tok_001",
)

print(f"Dynamic Token Generated: {token.dynamic_code} (Expires: {token.expires_at})")
```

---

### 2. Verify Session (Telemetric Presence & Attestation)

```python
from setsig import (
    Setsig,
    ReplayAttackError,
    GeofenceOutOfBoundsError,
    InsufficientCreditsError,
)

try:
    result = client.sessions.verify(
        venue_id="ven_ist_headquarters",
        token_id=token.token_id,
        client_token="device_bound_token_...",
        latitude=41.0082,
        longitude=28.9784,
        accuracy=4.2,
        attestation_token="hardware_attest_jwt_...",
        visual_proof_token="vpt_...",
    )
    print(f"Verified! Distance: {result.distance_meters}m, Risk: {result.risk_score}")
except ReplayAttackError as e:
    print(f"Security Alert: Double-spend / Replay detected: {e}")
except GeofenceOutOfBoundsError as e:
    print(f"Boundary Alert: User outside geofence perimeter: {e}")
except InsufficientCreditsError as e:
    print(f"Billing Alert: Credits exhausted: {e}")
```

---

### 3. Verify Incoming Webhooks (Timing-Safe Comparison)

Patent-protected replay resistance and timing attack mitigation:

```python
from setsig import Webhooks, SignatureVerificationError

webhooks = Webhooks(secret="whsec_...")

# Inside your FastAPI / Flask / Django request handler:
try:
    event = webhooks.construct_event(
        payload=raw_request_body_bytes,
        header=request.headers.get("X-Setsig-Signature"),
        tolerance=300.0,  # 5 minutes
    )
    
    if event.event == "session.verified":
        print(f"Session {event.data['session_id']} verified physically!")
    elif event.event == "venue.anomaly_detected":
        print(f"Venue alert: {event.data}")

except SignatureVerificationError as exc:
    # 401 Unauthorized
    print(f"Tampered webhook rejected: {exc}")
```

---

## Features

- **Zero External Dependencies:** No bloat, pure Python standard library.
- **Timing-Safe Cryptography:** Signature verification uses `hmac.compare_digest` to defend against timing side-channel attacks.
- **Automatic Retries & Exponential Backoff with Jitter:** Handles 429 Rate Limits and 5xx network interruptions gracefully.
- **Idempotency Keys:** Supports `idempotency_key` parameter to prevent accidental duplicate token generation or double-charges.
- **Typed Error Hierarchy:** Clean exceptions matching the setsig error model (`AuthenticationError`, `ReplayAttackError`, `GeofenceOutOfBoundsError`, `InsufficientCreditsError`, `RateLimitError`).

---

## License

Apache-2.0 License. Commercial verification engine intellectual property held by AVCI Ventures.

