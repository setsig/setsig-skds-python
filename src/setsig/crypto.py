"""Timing-safe cryptographic utilities for setsig webhook verification."""

import hmac
import hashlib
import time
from typing import Tuple

from .errors import SignatureVerificationError


def compute_signature(payload: bytes, timestamp: int, secret: str) -> str:
    """Computes the expected HMAC-SHA256 signature for a webhook payload."""
    signed_payload = f"t={timestamp}.".encode("utf-8") + payload
    mac = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256)
    return mac.hexdigest()


def parse_header(header: str) -> Tuple[int, str]:
    """Parses the X-Setsig-Signature header into (timestamp, signature)."""
    if not header:
        raise SignatureVerificationError("Missing X-Setsig-Signature header")

    timestamp_str = None
    signature = None

    for item in header.split(","):
        parts = item.strip().split("=", 1)
        if len(parts) == 2:
            key, value = parts[0].strip(), parts[1].strip()
            if key == "t":
                timestamp_str = value
            elif key == "v1":
                signature = value

    if not timestamp_str or not signature:
        raise SignatureVerificationError(
            "Malformed signature header format; expected t=timestamp,v1=signature"
        )

    try:
        timestamp = int(timestamp_str)
    except ValueError as exc:
        raise SignatureVerificationError("Invalid timestamp in signature header") from exc

    return timestamp, signature


def verify_signature(
    payload: bytes,
    header: str,
    secret: str,
    tolerance: float = 300.0,
) -> None:
    """
    Validates the authenticity of an incoming setsig webhook payload.

    Uses `hmac.compare_digest` to protect against side-channel timing attacks.
    Raises `SignatureVerificationError` if the signature is invalid or timestamp is outside tolerance.
    """
    timestamp, received_signature = parse_header(header)

    current_time = time.time()
    if abs(current_time - timestamp) > tolerance:
        raise SignatureVerificationError(
            f"Webhook timestamp expired or in future. Drift: {abs(current_time - timestamp):.1f}s > {tolerance}s"
        )

    expected_signature = compute_signature(payload, timestamp, secret)

    if not hmac.compare_digest(expected_signature, received_signature):
        raise SignatureVerificationError("Webhook signature verification failed")

