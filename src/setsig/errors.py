"""Exception hierarchy for the setsig Python SDK."""

from typing import Optional


class SetsigError(Exception):
    """Base exception for all setsig errors."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        code: Optional[str] = None,
        body: Optional[dict] = None,
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

