from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from tests.test_v3_12_policy_head_authority import PolicyHeadFixture
from triaxis.policy_head_http import PolicyHeadHTTPApplication


class PolicyHeadHTTPTests(unittest.TestCase):
    def test_health_and_challenge_response(self):
        fx = PolicyHeadFixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with fx.store(root / "policy.db") as store:
                fx.install(store, fx.policy1, fx.policy2)
                with fx.service(root / "responses.db", store) as service:
                    app = PolicyHeadHTTPApplication(service, clock=lambda: 9, response_ttl=10)
                    status, health = app.handle("GET", "/healthz")
                    self.assertEqual(status, 200)
                    self.assertEqual(health["policy_head"]["policy_version"], 2)
                    session, ledger, challenge = fx.challenge(root)
                    with ledger:
                        status, result = app.handle("POST", "/v1/head/challenge", {
                            "challenge": challenge,
                            "verifier_id": session.verifier_id,
                            "verifier_epoch_sha256": session.epoch_sha256,
                            "requested_at": 8,
                        })
                        self.assertEqual(status, 200, result)
                        policy = fx.load(store, result["signed_policy_head"], ledger, challenge)
                    self.assertEqual(policy["policy_version"], 2)

    def test_policy_install_endpoint_is_disabled_without_admin_token(self):
        fx = PolicyHeadFixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with fx.store(root / "policy.db") as store:
                fx.install(store, fx.policy1)
                with fx.service(root / "responses.db", store) as service:
                    app = PolicyHeadHTTPApplication(service, clock=lambda: 5)
                    status, result = app.handle("POST", "/v1/policies/install", {
                        "signed_policy": fx.managed.signed_policy(fx.policy2),
                    })
        self.assertEqual(status, 403)
        self.assertEqual(result["error"], "administrative_authorization_required")

    def test_policy_install_requires_exact_bearer_token(self):
        fx = PolicyHeadFixture()
        token = "admin-secret-with-enough-entropy"
        token_sha = hashlib.sha256(token.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with fx.store(root / "policy.db") as store:
                fx.install(store, fx.policy1)
                with fx.service(root / "responses.db", store) as service:
                    app = PolicyHeadHTTPApplication(service, clock=lambda: 6, admin_token_sha256=token_sha)
                    denied, _ = app.handle("POST", "/v1/policies/install", {
                        "signed_policy": fx.managed.signed_policy(fx.policy2),
                    }, {"Authorization": "Bearer wrong"})
                    accepted, result = app.handle("POST", "/v1/policies/install", {
                        "signed_policy": fx.managed.signed_policy(fx.policy2),
                    }, {"Authorization": f"Bearer {token}"})
        self.assertEqual(denied, 403)
        self.assertEqual(accepted, 200, result)
        self.assertEqual(result["head"]["policy_version"], 2)

    def test_unknown_path_and_invalid_body_fail_closed(self):
        fx = PolicyHeadFixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with fx.store(root / "policy.db") as store:
                fx.install(store, fx.policy1)
                with fx.service(root / "responses.db", store) as service:
                    app = PolicyHeadHTTPApplication(service, clock=lambda: 9)
                    self.assertEqual(app.handle("GET", "/unknown")[0], 404)
                    status, result = app.handle("POST", "/v1/head/challenge", "bad")
        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "invalid_json_object")


if __name__ == "__main__":
    unittest.main()
