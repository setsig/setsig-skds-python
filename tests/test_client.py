import io
import json
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from setsig import (
    Setsig,
    AuthenticationError,
    ReplayAttackError,
    GeofenceOutOfBoundsError,
    RateLimitError,
    TokenFormat,
)


class TestSetsigClient(unittest.TestCase):
    def setUp(self):
        self.client = Setsig(api_key="test_api_key_valid", max_retries=0)

    def test_missing_api_key(self):
        with self.assertRaises(AuthenticationError):
            Setsig(api_key="")

    @patch("urllib.request.urlopen")
    def test_tokens_generate(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "token_id": "tok_123",
                "venue_id": "ven_1",
                "dynamic_code": "993812",
                "expires_at": "2026-11-04T12:00:00Z",
                "payload": "setsig://v1/t/tok_123?c=993812",
                "qr_svg": "<svg></svg>",
            }
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.tokens.generate(
            venue_id="ven_1",
            ttl=60,
            format=TokenFormat.SVG,
            idempotency_key="idemp_python_1",
        )

        self.assertEqual(res.token_id, "tok_123")
        self.assertEqual(res.dynamic_code, "993812")
        self.assertEqual(res.qr_svg, "<svg></svg>")

    @patch("urllib.request.urlopen")
    def test_sessions_verify(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "session_id": "ses_python_1",
                "tenant_id": "ten_1",
                "venue_id": "ven_1",
                "status": "VERIFIED",
                "verified_at": "2026-11-04T12:00:00Z",
                "distance_meters": 3.8,
                "risk_score": 0.01,
                "visual_proof": {
                    "status": "PASSED",
                    "liveness_score": 0.98,
                    "visual_tamper_score": 0.02,
                    "captured_at": "2026-11-04T12:00:00Z",
                },
                "claim_tokens": ["claim_abc"],
            }
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = self.client.sessions.verify(
            venue_id="ven_1",
            token_id="tok_123",
            client_token="client_tok_xyz",
            latitude=41.0082,
            longitude=28.9784,
            accuracy=4.0,
        )

        self.assertEqual(res.session_id, "ses_python_1")
        self.assertEqual(res.status, "VERIFIED")
        self.assertIsNotNone(res.visual_proof)
        self.assertEqual(res.visual_proof.liveness_score, 0.98)

    @patch("urllib.request.urlopen")
    def test_venues_crud(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "id": "ven_py_1",
                "tenant_id": "ten_1",
                "name": "Ankara Hub",
                "latitude": 39.9334,
                "longitude": 32.8597,
                "radius_meters": 50.0,
                "strict_attestation": True,
                "strict_visual_proof": False,
                "status": "ACTIVE",
                "created_at": "2026-11-04T12:00:00Z",
                "updated_at": "2026-11-04T12:00:00Z",
            }
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        venue = self.client.venues.create(
            name="Ankara Hub",
            latitude=39.9334,
            longitude=32.8597,
            radius_meters=50.0,
            strict_attestation=True,
        )
        self.assertEqual(venue.id, "ven_py_1")
        self.assertEqual(venue.name, "Ankara Hub")

    @patch("urllib.request.urlopen")
    def test_billing_balance(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "data": {
                "balance_credits": 15000,
                "currency": "USD",
                "tier": "GROWTH",
                "auto_topup": False,
            }
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        balance = self.client.billing.get_balance()
        self.assertEqual(balance.balance_credits, 15000)
        self.assertEqual(balance.tier, "GROWTH")

    @patch("urllib.request.urlopen")
    def test_error_mapping_replay(self, mock_urlopen):
        err_body = json.dumps({"error": "Replay attack detected", "code": "DOUBLE_SPEND_REPLAY_ATTACK"}).encode("utf-8")
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=409,
            msg="Conflict",
            hdrs={},
            fp=io.BytesIO(err_body),
        )

        with self.assertRaises(ReplayAttackError):
            self.client.tokens.generate(venue_id="ven_1")

    @patch("urllib.request.urlopen")
    def test_error_mapping_geofence(self, mock_urlopen):
        err_body = json.dumps({"error": "Outside venue geofence", "code": "GEOFENCE_BREACH"}).encode("utf-8")
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=422,
            msg="Unprocessable Entity",
            hdrs={},
            fp=io.BytesIO(err_body),
        )

        with self.assertRaises(GeofenceOutOfBoundsError):
            self.client.tokens.generate(venue_id="ven_1")

    @patch("urllib.request.urlopen")
    def test_error_mapping_ratelimit(self, mock_urlopen):
        err_body = json.dumps({"error": "Rate limit exceeded"}).encode("utf-8")
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test",
            code=429,
            msg="Too Many Requests",
            hdrs={"Retry-After": "60"},
            fp=io.BytesIO(err_body),
        )

        with self.assertRaises(RateLimitError) as cm:
            self.client.tokens.generate(venue_id="ven_1")
        self.assertEqual(cm.exception.retry_after, 60)


if __name__ == "__main__":
    unittest.main()
