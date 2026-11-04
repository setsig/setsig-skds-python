"""Webhook event construction and framework helpers."""

import json
from typing import Any, Callable, Optional, Union

from .crypto import verify_signature
from .errors import SignatureVerificationError
from .types import WebhookEvent


class Webhooks:
    """Namespace for webhook cryptographic verification and event parsing."""

    def __init__(self, secret: Optional[str] = None):
        self.secret = secret

    def construct_event(
        self,
        payload: Union[bytes, str],
        header: str,
        secret: Optional[str] = None,
        tolerance: float = 300.0,
    ) -> WebhookEvent:
        """
        Parses and cryptographically verifies an incoming setsig webhook.

        Args:
            payload: Raw request body as bytes or string.
            header: Value of X-Setsig-Signature header.
            secret: Webhook signing secret (falls back to client configured secret).
            tolerance: Maximum permissible clock drift in seconds (default: 300s).

        Returns:
            Validated WebhookEvent instance.
        """
        signing_secret = secret or self.secret
        if not signing_secret:
            raise SignatureVerificationError("Webhook secret must be provided")

        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload

        verify_signature(payload_bytes, header, signing_secret, tolerance=tolerance)

        try:
            data = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise SignatureVerificationError(f"Failed to decode webhook JSON: {exc}") from exc

        return WebhookEvent(
            id=data.get("id", ""),
            event=data.get("event", ""),
            timestamp=data.get("timestamp", 0),
            data=data.get("data", {}),
        )


def create_flask_webhook_view(
    secret: str,
    event_handler: Callable[[WebhookEvent], Any],
    tolerance: float = 300.0,
):
    """
    Creates a Flask-compatible view function for setsig webhooks.
    """
    try:
        from flask import request, jsonify, abort  # type: ignore
    except ImportError:
        raise ImportError("Flask is not installed. Install with `pip install flask`")

    webhooks = Webhooks(secret=secret)

    def view():
        header = request.headers.get("X-Setsig-Signature")
        if not header:
            abort(400, "Missing X-Setsig-Signature header")

        try:
            event = webhooks.construct_event(
                request.get_data(), header, tolerance=tolerance
            )
        except SignatureVerificationError as exc:
            abort(401, str(exc))

        result = event_handler(event)
        return jsonify({"received": True, "result": result}), 200

    return view

