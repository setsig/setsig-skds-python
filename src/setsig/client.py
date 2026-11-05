"""setsig client implementation using standard library HTTP transport."""

import json
import random
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Union

from .errors import (
    AuthenticationError,
    GeofenceOutOfBoundsError,
    InsufficientCreditsError,
    PaywallBlockedError,
    CrossBorderCreditRequiredError,
    PaywallTierRequiredError,
    AttestationFailedError,
    VisualProofRequiredError,
    StaleVisualProofError,
    InvalidImageHashError,
    RateLimitError,
    ReplayAttackError,
    SetsigError,
)
from .types import (
    BillingBalance,
    EstimateCostResponse,
    GenerateTokenResponse,
    TerminalSessionResponse,
    TokenFormat,
    Venue,
    VerifySessionResponse,
    VisualProofPayload,
    VisualProofSummary,
)
from .webhooks import Webhooks

DEFAULT_BASE_URL = "https://api.setsig.com"
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_RETRIES = 3
SDK_VERSION = "0.8.0"


class _HTTPClient:
    """Internal HTTP client with automatic retries and exponential backoff."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max(0, max_retries)

    def request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None

        backoff = 0.2
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                jitter = random.uniform(0.0, 0.1)
                time.sleep(backoff + jitter)
                backoff *= 2

            req = urllib.request.Request(url, data=data_bytes, method=method)
            req.add_header("Authorization", f"Bearer {self.api_key}")
            req.add_header("Content-Type", "application/json")
            req.add_header("Accept", "application/json")
            req.add_header("User-Agent", f"setsig-python/{SDK_VERSION}")
            if idempotency_key:
                req.add_header("Idempotency-Key", idempotency_key)

            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_body = resp.read()
                    if not resp_body:
                        return {}
                    return json.loads(resp_body.decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raw_err = exc.read().decode("utf-8")
                err_dict = {}
                try:
                    err_dict = json.loads(raw_err)
                except Exception:
                    pass

                err_msg = err_dict.get("message") or err_dict.get("error") or exc.reason
                code = err_dict.get("code")
                status = exc.code

                if status == 429:
                    retry_after_hdr = exc.headers.get("Retry-After")
                    retry_after = int(retry_after_hdr) if retry_after_hdr and retry_after_hdr.isdigit() else None
                    rate_err = RateLimitError(
                        message=err_msg,
                        status_code=status,
                        retry_after=retry_after,
                        code=code,
                    )
                    last_error = rate_err
                    if attempt < self.max_retries:
                        if retry_after:
                            backoff = float(retry_after)
                        continue
                    raise rate_err

                if status >= 500 and attempt < self.max_retries:
                    last_error = SetsigError(
                        message=err_msg,
                        status_code=status,
                        code=code,
                        body=err_dict,
                    )
                    continue

                if code == "ERR_PAYWALL_BLOCKED":
                    raise PaywallBlockedError(message=err_msg, status_code=status, code=code, body=err_dict)
                if code == "ERR_CROSS_BORDER_CREDIT_REQUIRED":
                    raise CrossBorderCreditRequiredError(message=err_msg, status_code=status, code=code, body=err_dict)
                if code == "ERR_PAYWALL_TIER_REQUIRED":
                    raise PaywallTierRequiredError(message=err_msg, status_code=status, code=code, body=err_dict)
                if code == "ERR_ATTESTATION_FAILED":
                    raise AttestationFailedError(message=err_msg, status_code=status, code=code, body=err_dict)
                if code == "ERR_VISUAL_PROOF_REQUIRED":
                    raise VisualProofRequiredError(message=err_msg, status_code=status, code=code, body=err_dict)
                if code == "ERR_STALE_VISUAL_PROOF":
                    raise StaleVisualProofError(message=err_msg, status_code=status, code=code, body=err_dict)
                if code == "ERR_INVALID_IMAGE_HASH":
                    raise InvalidImageHashError(message=err_msg, status_code=status, code=code, body=err_dict)

                if status in (401, 403):
                    raise AuthenticationError(
                        message=err_msg,
                        status_code=status,
                        code=code,
                        body=err_dict,
                    )
                if status == 402:
                    raise InsufficientCreditsError(
                        message=err_msg,
                        status_code=status,
                        code=code,
                        body=err_dict,
                    )
                if status == 409 and (code == "DOUBLE_SPEND_REPLAY_ATTACK" or "replay" in err_msg.lower()):
                    raise ReplayAttackError(
                        message=err_msg,
                        status_code=status,
                        code=code,
                        body=err_dict,
                    )
                if status == 422 and ("geofence" in err_msg.lower() or "distance" in err_msg.lower()):
                    raise GeofenceOutOfBoundsError(
                        message=err_msg,
                        status_code=status,
                        code=code,
                        body=err_dict,
                    )

                raise SetsigError(
                    message=err_msg,
                    status_code=status,
                    code=code,
                    body=err_dict,
                )
            except urllib.error.URLError as exc:
                last_error = exc
                continue

        if last_error:
            if isinstance(last_error, SetsigError):
                raise last_error
            raise SetsigError(f"Network error: {last_error}")
        raise SetsigError("Request failed after retries")


class TokensResource:
    """Manages dynamic presence TOTP tokens."""

    def __init__(self, http_client: _HTTPClient):
        self._http = http_client

    def generate(
        self,
        venue_id: str,
        ttl: int = 60,
        format: Union[TokenFormat, str] = TokenFormat.RAW,
        metadata: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> GenerateTokenResponse:
        fmt_val = format.value if isinstance(format, TokenFormat) else format
        payload: Dict[str, Any] = {
            "venue_id": venue_id,
            "ttl": ttl,
            "format": fmt_val,
        }
        if metadata:
            payload["metadata"] = metadata

        res = self._http.request(
            "POST",
            "/v1/tokens/generate",
            body=payload,
            idempotency_key=idempotency_key,
        )
        data = res.get("data", res)
        return GenerateTokenResponse(
            token_id=data["token_id"],
            venue_id=data["venue_id"],
            dynamic_code=data["dynamic_code"],
            expires_at=data["expires_at"],
            payload=data["payload"],
            qr_data_url=data.get("qr_data_url"),
            qr_svg=data.get("qr_svg"),
        )


class SessionsResource:
    """Manages physical presence verification sessions."""

    def __init__(self, http_client: _HTTPClient):
        self._http = http_client

    def verify(
        self,
        venue_id: str,
        token_id: str,
        client_token: str,
        latitude: float,
        longitude: float,
        accuracy: float,
        altitude: Optional[float] = None,
        speed: Optional[float] = None,
        heading: Optional[float] = None,
        attestation_token: Optional[str] = None,
        visual_proof_token: Optional[str] = None,
        client_ip: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> VerifySessionResponse:
        payload: Dict[str, Any] = {
            "venue_id": venue_id,
            "token_id": token_id,
            "client_token": client_token,
            "latitude": latitude,
            "longitude": longitude,
            "accuracy": accuracy,
        }
        if altitude is not None:
            payload["altitude"] = altitude
        if speed is not None:
            payload["speed"] = speed
        if heading is not None:
            payload["heading"] = heading
        if attestation_token is not None:
            payload["attestation_token"] = attestation_token
        if visual_proof_token is not None:
            payload["visual_proof_token"] = visual_proof_token
        if client_ip is not None:
            payload["client_ip"] = client_ip

        res = self._http.request(
            "POST",
            "/v1/sessions/verify",
            body=payload,
            idempotency_key=idempotency_key,
        )
        data = res.get("data", res)

        visual_proof = None
        if data.get("visual_proof"):
            vp = data["visual_proof"]
            visual_proof = VisualProofSummary(
                status=vp.get("status", "UNKNOWN"),
                liveness_score=vp.get("liveness_score", 0.0),
                visual_tamper_score=vp.get("visual_tamper_score", 0.0),
                captured_at=vp.get("captured_at", ""),
                storage_key=vp.get("storage_key"),
                analysis_notes=vp.get("analysis_notes", []),
            )

        return VerifySessionResponse(
            session_id=data["session_id"],
            tenant_id=data["tenant_id"],
            venue_id=data["venue_id"],
            status=data["status"],
            verified_at=data["verified_at"],
            distance_meters=data["distance_meters"],
            risk_score=data["risk_score"],
            visual_proof=visual_proof,
            claim_tokens=data.get("claim_tokens", []),
        )

    def get(self, session_id: str) -> VerifySessionResponse:
        res = self._http.request("GET", f"/v1/sessions/{session_id}")
        data = res.get("data", res)

        visual_proof = None
        if data.get("visual_proof"):
            vp = data["visual_proof"]
            visual_proof = VisualProofSummary(
                status=vp.get("status", "UNKNOWN"),
                liveness_score=vp.get("liveness_score", 0.0),
                visual_tamper_score=vp.get("visual_tamper_score", 0.0),
                captured_at=vp.get("captured_at", ""),
                storage_key=vp.get("storage_key"),
                analysis_notes=vp.get("analysis_notes", []),
            )

        return VerifySessionResponse(
            session_id=data["session_id"],
            tenant_id=data["tenant_id"],
            venue_id=data["venue_id"],
            status=data["status"],
            verified_at=data["verified_at"],
            distance_meters=data["distance_meters"],
            risk_score=data["risk_score"],
            visual_proof=visual_proof,
            claim_tokens=data.get("claim_tokens", []),
        )


class VenuesResource:
    """Manages physical venues and geofence perimeters."""

    def __init__(self, http_client: _HTTPClient):
        self._http = http_client

    def create(
        self,
        name: str,
        latitude: float,
        longitude: float,
        radius_meters: float,
        strict_attestation: bool = False,
        strict_visual_proof: bool = False,
    ) -> Venue:
        payload = {
            "name": name,
            "latitude": latitude,
            "longitude": longitude,
            "radius_meters": radius_meters,
            "strict_attestation": strict_attestation,
            "strict_visual_proof": strict_visual_proof,
        }
        res = self._http.request("POST", "/v1/venues", body=payload)
        data = res.get("data", res)
        return Venue(
            id=data["id"],
            tenant_id=data["tenant_id"],
            name=data["name"],
            latitude=data["latitude"],
            longitude=data["longitude"],
            radius_meters=data["radius_meters"],
            strict_attestation=data["strict_attestation"],
            strict_visual_proof=data["strict_visual_proof"],
            status=data["status"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            dynamic_seed_secret=data.get("dynamic_seed_secret"),
        )

    def get(self, venue_id: str) -> Venue:
        res = self._http.request("GET", f"/v1/venues/{venue_id}")
        data = res.get("data", res)
        return Venue(
            id=data["id"],
            tenant_id=data["tenant_id"],
            name=data["name"],
            latitude=data["latitude"],
            longitude=data["longitude"],
            radius_meters=data["radius_meters"],
            strict_attestation=data["strict_attestation"],
            strict_visual_proof=data["strict_visual_proof"],
            status=data["status"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            dynamic_seed_secret=data.get("dynamic_seed_secret"),
        )

    def list(self, limit: Optional[int] = None, offset: Optional[int] = None) -> List[Venue]:
        params = []
        if limit is not None:
            params.append(f"limit={limit}")
        if offset is not None:
            params.append(f"offset={offset}")
        query = f"?{'&'.join(params)}" if params else ""

        res = self._http.request("GET", f"/v1/venues{query}")
        data = res.get("data", res)
        venues_raw = data.get("venues", data if isinstance(data, list) else [])
        return [
            Venue(
                id=v["id"],
                tenant_id=v["tenant_id"],
                name=v["name"],
                latitude=v["latitude"],
                longitude=v["longitude"],
                radius_meters=v["radius_meters"],
                strict_attestation=v["strict_attestation"],
                strict_visual_proof=v["strict_visual_proof"],
                status=v["status"],
                created_at=v["created_at"],
                updated_at=v["updated_at"],
                dynamic_seed_secret=v.get("dynamic_seed_secret"),
            )
            for v in venues_raw
        ]

    def update(
        self,
        venue_id: str,
        name: Optional[str] = None,
        radius_meters: Optional[float] = None,
        strict_attestation: Optional[bool] = None,
        strict_visual_proof: Optional[bool] = None,
    ) -> Venue:
        payload: Dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if radius_meters is not None:
            payload["radius_meters"] = radius_meters
        if strict_attestation is not None:
            payload["strict_attestation"] = strict_attestation
        if strict_visual_proof is not None:
            payload["strict_visual_proof"] = strict_visual_proof

        res = self._http.request("PATCH", f"/v1/venues/{venue_id}", body=payload)
        data = res.get("data", res)
        return Venue(
            id=data["id"],
            tenant_id=data["tenant_id"],
            name=data["name"],
            latitude=data["latitude"],
            longitude=data["longitude"],
            radius_meters=data["radius_meters"],
            strict_attestation=data["strict_attestation"],
            strict_visual_proof=data["strict_visual_proof"],
            status=data["status"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            dynamic_seed_secret=data.get("dynamic_seed_secret"),
        )

    def rotate_secret(self, venue_id: str) -> Dict[str, Any]:
        """Rotates cryptographic TOTP secret for a venue."""
        res = self._http.request("POST", f"/v1/venues/{venue_id}/rotate-secret")
        return res.get("data", res)

    def delete(self, venue_id: str) -> None:
        self._http.request("DELETE", f"/v1/venues/{venue_id}")


class TerminalsResource:
    """Manages kiosk displays and Gatekeeper turnstile sessions."""

    def __init__(self, http_client: _HTTPClient):
        self._http = http_client

    def create_session(self, terminal_key: str, venue_id: str) -> TerminalSessionResponse:
        payload = {
            "terminal_key": terminal_key,
            "venue_id": venue_id,
        }
        res = self._http.request("POST", "/v1/terminals/session", body=payload)
        data = res.get("data", res)
        return TerminalSessionResponse(
            status=data.get("status", "authenticated"),
            terminal_session_token=data.get("terminal_session_token", ""),
            venue_name=data.get("venue_name", "Turnstile Display"),
            totp_interval_seconds=data.get("totp_interval_seconds", 60),
            scope=data.get("scope", "tokens:generate_only"),
        )


class BillingResource:
    """Manages ledger balances and geo-cost estimates."""

    def __init__(self, http_client: _HTTPClient):
        self._http = http_client

    def get_balance(self) -> BillingBalance:
        res = self._http.request("GET", "/v1/billing/balance")
        data = res.get("data", res)
        return BillingBalance(
            balance_credits=data["balance_credits"],
            currency=data["currency"],
            tier=data["tier"],
            auto_topup=data["auto_topup"],
        )

    def estimate_cost(
        self,
        country_code: str,
        strict_attestation: bool,
        strict_visual_proof: bool,
        quantity: int,
    ) -> EstimateCostResponse:
        payload = {
            "country_code": country_code,
            "strict_attestation": strict_attestation,
            "strict_visual_proof": strict_visual_proof,
            "quantity": quantity,
        }
        res = self._http.request("POST", "/v1/billing/estimate", body=payload)
        data = res.get("data", res)
        return EstimateCostResponse(
            unit_cost_credits=data["unit_cost_credits"],
            total_cost_credits=data["total_cost_credits"],
            geo_multiplier=data["geo_multiplier"],
            currency=data["currency"],
        )


class Setsig:
    """The primary client for setsig infrastructure."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        webhook_secret: Optional[str] = None,
    ):
        if not api_key:
            raise AuthenticationError("API key must be provided")

        self._http = _HTTPClient(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
        )

        self.tokens = TokensResource(self._http)
        self.sessions = SessionsResource(self._http)
        self.venues = VenuesResource(self._http)
        self.billing = BillingResource(self._http)
        self.terminals = TerminalsResource(self._http)
        self.webhooks = Webhooks(secret=webhook_secret)

