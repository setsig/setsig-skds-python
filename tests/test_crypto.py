import time
import unittest

from setsig import compute_signature, verify_signature, SignatureVerificationError, Webhooks


class TestCryptoAndWebhooks(unittest.TestCase):
    def setUp(self):
        self.secret = "whsec_test_python_secret_123"
        self.payload = b'{"id":"evt_1","event":"session.verified","timestamp":1700000000}'

    def test_compute_signature_deterministic(self):
        timestamp = 1700000000
        sig1 = compute_signature(self.payload, timestamp, self.secret)
        sig2 = compute_signature(self.payload, timestamp, self.secret)
        self.assertTrue(len(sig1) > 0)
        self.assertEqual(sig1, sig2)

    def test_verify_signature_valid(self):
        now = int(time.time())
        sig = compute_signature(self.payload, now, self.secret)
        header = f"t={now},v1={sig}"
        # Should not raise
        verify_signature(self.payload, header, self.secret, tolerance=300.0)

    def test_verify_signature_invalid_sig(self):
        now = int(time.time())
        header = f"t={now},v1=wrong_hex_signature"
        with self.assertRaises(SignatureVerificationError):
            verify_signature(self.payload, header, self.secret, tolerance=300.0)

    def test_verify_signature_expired(self):
        expired = int(time.time()) - 600
        sig = compute_signature(self.payload, expired, self.secret)
        header = f"t={expired},v1={sig}"
        with self.assertRaises(SignatureVerificationError):
            verify_signature(self.payload, header, self.secret, tolerance=300.0)

    def test_webhooks_construct_event(self):
        webhooks = Webhooks(secret=self.secret)
        now = int(time.time())
        payload = b'{"id":"evt_web_1","event":"session.verified","timestamp":1700000000,"data":{"status":"VERIFIED"}}'
        sig = compute_signature(payload, now, self.secret)
        header = f"t={now},v1={sig}"

        event = webhooks.construct_event(payload, header)
        self.assertEqual(event.id, "evt_web_1")
        self.assertEqual(event.event, "session.verified")
        self.assertEqual(event.data["status"], "VERIFIED")


if __name__ == "__main__":
    unittest.main()

