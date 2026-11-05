"""Exception hierarchy for the setsig Python SDK."""

from typing import Optional, Any, Dict


class SetsigError(Exception):
    """Base exception for all setsig errors."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
        body: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.body = body

    def __str__(self) -> str:
        if self.status_code and self.code:
            return f"SetsigError (HTTP {self.status_code} - {self.code}): {self.message}"
        if self.status_code:
            return f"SetsigError (HTTP {self.status_code}): {self.message}"
        return f"SetsigError: {self.message}"


class AuthenticationError(SetsigError):
    """Raised when authentication fails due to invalid or missing API key (HTTP 401/403)."""


class InsufficientCreditsError(SetsigError):
    """Raised when account credit balance is depleted (HTTP 402)."""


class PaywallBlockedError(SetsigError):
    """Raised when verification services are locked due to zero/depleted prepaid balance (HTTP 402)."""

    def __init__(
        self,
        message: str = "Verification services locked due to depleted prepaid balance",
        status_code: int = 402,
        code: str = "ERR_PAYWALL_BLOCKED",
        body: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, status_code=status_code, code=code, body=body)
        details = (body or {}).get("details", {})
        self.paywall_url: Optional[str] = details.get("paywall_url")
        self.current_balance: Optional[float] = details.get("current_balance")
        self.required_min_topup: Optional[float] = details.get("required_min_topup")
        self.currency: Optional[str] = details.get("currency")


class CrossBorderCreditRequiredError(SetsigError):
    """Raised when verifying at an international venue without local currency or FX buffer (HTTP 402)."""


class PaywallTierRequiredError(SetsigError):
    """Raised when requested feature requires a higher tier plan or subscription (HTTP 403)."""


class AttestationFailedError(SetsigError):
    """Raised when hardware attestation fails due to rooted device or emulator (HTTP 403)."""


class VisualProofRequiredError(SetsigError):
    """Raised when venue policy mandates photographic proof of presence (HTTP 422)."""


class StaleVisualProofError(SetsigError):
    """Raised when photo timestamp exceeds 10-second cryptographic tolerance (HTTP 400)."""


class InvalidImageHashError(SetsigError):
    """Raised when photo SHA-256 hash does not match uploaded cloud image (HTTP 400)."""


class ReplayAttackError(SetsigError):
    """Raised when a dynamic token or client device token is reused / double-spent (HTTP 409)."""


class GeofenceOutOfBoundsError(SetsigError):
    """Raised when physical client telemetry fails venue perimeter constraints (HTTP 422)."""


class RateLimitError(SetsigError):
    """Raised when requests exceed configured tenant rate limits (HTTP 429)."""

    def __init__(
        self,
        message: str,
        status_code: int = 429,
        retry_after: Optional[int] = None,
        code: Optional[str] = None,
    ):
        super().__init__(message, status_code=status_code, code=code)
        self.retry_after = retry_after

    def __str__(self) -> str:
        if self.retry_after:
            return f"RateLimitError: Rate limit exceeded. Retry after {self.retry_after}s: {self.message}"
        return f"RateLimitError: {self.message}"


class SignatureVerificationError(SetsigError):
    """Raised when webhook signature verification fails or timestamp expired."""
