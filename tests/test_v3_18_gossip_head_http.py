from __future__ import annotations

import hashlib
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path

from tests.test_v3_16_external_gossip_head import ExternalGossipHeadFixture
from triaxis.policy_transparency_gossip_head_http import GossipHeadHTTPApplication


class GossipHeadHTTPTests(unittest.TestCase):
    def test_health_install_and_challenge(self):
        fx = ExternalGossipHeadFixture()
        token = "admin-token-with-enough-entropy"
        token_sha = hashlib.sha256(token.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            root = Path(tmp)
            gossip = fx.populate(stack, root / "gossip", 2)
            issuer = fx.issuer(stack, root / "issuer", gossip)
            checkpoint = issuer.issue(issued_at=10, valid_until=100)
            authority = fx.authority(stack, root)
            app = GossipHeadHTTPApplication(
                authority,
                clock=lambda: 12,
                response_ttl=10,
                admin_token_sha256=token_sha,
            )
            status, health = app.handle("GET", "/healthz")
            self.assertEqual(status, 200)
            self.assertIsNone(health["current"])
            denied, _ = app.handle(
                "POST",
                "/v1/checkpoints/install",
                {"signed_checkpoint": checkpoint},
                {"Authorization": "Bearer wrong"},
            )
            accepted, installed = app.handle(
                "POST",
                "/v1/checkpoints/install",
                {"signed_checkpoint": checkpoint},
                {"Authorization": f"Bearer {token}"},
            )
            head_status, result = app.handle(
                "POST",
                "/v1/head/challenge",
                {
                    "store_id": fx.store_id,
                    "challenge": "challenge-with-minimum-length",
                    "verifier_id": "verifier:http-test",
                    "verifier_epoch_sha256": "0" * 64,
                    "requested_at": 10,
                },
            )
        self.assertEqual(denied, 403)
        self.assertEqual(accepted, 200, installed)
        self.assertEqual(installed["checkpoint"]["checkpoint_sequence"], 1)
        self.assertEqual(head_status, 200, result)
        self.assertIn("signed_gossip_head", result)

    def test_fail_closed_for_unknown_store_invalid_body_and_unknown_path(self):
        fx = ExternalGossipHeadFixture()
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            authority = fx.authority(stack, Path(tmp))
            app = GossipHeadHTTPApplication(authority, clock=lambda: 12)
            bad_body, result = app.handle("POST", "/v1/head/challenge", "bad")
            unknown_store, store_result = app.handle(
                "POST",
                "/v1/head/challenge",
                {
                    "store_id": "missing",
                    "challenge": "challenge-with-minimum-length",
                    "verifier_id": "verifier:x",
                    "verifier_epoch_sha256": "0" * 64,
                    "requested_at": 10,
                },
            )
            missing = app.handle("GET", "/missing")[0]
        self.assertEqual(bad_body, 400)
        self.assertEqual(result["error"], "invalid_json_object")
        self.assertEqual(unknown_store, 409)
        self.assertEqual(store_result["error"], "unknown_gossip_store")
        self.assertEqual(missing, 404)


if __name__ == "__main__":
    unittest.main()
