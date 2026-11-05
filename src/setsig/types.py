"""Data models and type definitions for setsig Python SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TokenFormat(str, Enum):
    RAW = "raw"
    DATA_URL = "data_url"
    SVG = "svg"


@dataclass
class GenerateTokenRequest:
    venue_id: str
    ttl: int = 60
    format: TokenFormat = TokenFormat.RAW
    metadata: Optional[Dict[str, str]] = None


@dataclass
class GenerateTokenResponse:
    token_id: str
    venue_id: str
    dynamic_code: str
    expires_at: str
    payload: str
    qr_data_url: Optional[str] = None
    qr_svg: Optional[str] = None


@dataclass
class VisualProofPayload:
    image_hash_sha256: str
    storage_key: str
    captured_at: str
    liveness_score: Optional[float] = None


@dataclass
class VerifySessionRequest:
    venue_id: str
    token_id: str
    client_token: str
    latitude: float
    longitude: float
    accuracy: float
    altitude: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    attestation_token: Optional[str] = None
    visual_proof_token: Optional[str] = None
    visual_proof: Optional[VisualProofPayload] = None
    client_ip: Optional[str] = None


@dataclass
class VisualProofSummary:
    status: str
    liveness_score: float
    visual_tamper_score: float
    captured_at: str
    storage_key: Optional[str] = None
    analysis_notes: List[str] = field(default_factory=list)


@dataclass
class VerifySessionResponse:
    session_id: str
    tenant_id: str
    venue_id: str
    status: str
    verified_at: str
    distance_meters: float
    risk_score: float
    visual_proof: Optional[VisualProofSummary] = None
    claim_tokens: List[str] = field(default_factory=list)


@dataclass
class Venue:
    id: str
    tenant_id: str
    name: str
    latitude: float
    longitude: float
    radius_meters: float
    strict_attestation: bool
    strict_visual_proof: bool
    status: str
    created_at: str
    updated_at: str
    reference_id: Optional[str] = None
    country_code: Optional[str] = None
    hardware_profile: Optional[str] = None
    hardware_config: Optional[Dict[str, Any]] = None
    visual_proof_prompt: Optional[str] = None
    dynamic_seed_secret: Optional[str] = None


@dataclass
class CreateVenueRequest:
    name: str
    latitude: float
    longitude: float
    radius_meters: float
    reference_id: Optional[str] = None
    country_code: Optional[str] = None
    hardware_profile: Optional[str] = None
    hardware_config: Optional[Dict[str, Any]] = None
    strict_attestation: bool = False
    strict_visual_proof: bool = False
    visual_proof_prompt: Optional[str] = None


@dataclass
class UpdateVenueRequest:
    name: Optional[str] = None
    reference_id: Optional[str] = None
    country_code: Optional[str] = None
    radius_meters: Optional[float] = None
    hardware_profile: Optional[str] = None
    hardware_config: Optional[Dict[str, Any]] = None
    strict_attestation: Optional[bool] = None
    strict_visual_proof: Optional[bool] = None
    visual_proof_prompt: Optional[str] = None


@dataclass
class TerminalSessionRequest:
    terminal_key: str
    venue_id: str


@dataclass
class TerminalSessionResponse:
    status: str
    terminal_session_token: str
    venue_name: str
    totp_interval_seconds: int
    scope: str


@dataclass
class BillingBalance:
    balance_credits: int
    currency: str
    tier: str
    auto_topup: bool


@dataclass
class EstimateCostRequest:
    country_code: str
    strict_attestation: bool
    strict_visual_proof: bool
    quantity: int


@dataclass
class EstimateCostResponse:
    unit_cost_credits: int
    total_cost_credits: int
    geo_multiplier: float
    currency: str


@dataclass
class WebhookEvent:
    id: str
    event: str
    timestamp: int
    data: Dict[str, Any]

