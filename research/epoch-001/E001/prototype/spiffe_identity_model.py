import os
import sys
import time
import hmac
import hashlib
import json
import base64
from typing import Dict, Any, Optional, List, Tuple

class SPIFFEID:
    def __init__(self, trust_domain: str, path: str):
        if not trust_domain:
            raise ValueError("Trust domain cannot be empty")
        if not path.startswith("/"):
            path = "/" + path
        self.trust_domain = trust_domain
        self.path = path

    def uri(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"

    def __eq__(self, other):
        return isinstance(other, SPIFFEID) and self.uri() == other.uri()

    def __repr__(self):
        return self.uri()

class WorkloadAttestor:
    @staticmethod
    def attest_current_process() -> Dict[str, Any]:
        return {
            "pid": os.getpid(),
            "uid": os.getuid() if hasattr(os, "getuid") else 1000,
            "executable": sys.executable,
            "platform": sys.platform
        }

class SVID:
    def __init__(self, spiffe_id: SPIFFEID, issued_at: float, ttl_seconds: float, signature: str, payload: Dict[str, Any]):
        self.spiffe_id = spiffe_id
        self.issued_at = issued_at
        self.ttl_seconds = ttl_seconds
        self.expires_at = issued_at + ttl_seconds
        self.signature = signature
        self.payload = payload

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at

    def to_jwt(self) -> str:
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps({
            "sub": self.spiffe_id.uri(),
            "iat": int(self.issued_at),
            "exp": int(self.expires_at),
            "payload": self.payload
        }).encode()).decode().rstrip("=")
        return f"{header}.{body}.{self.signature}"

class SPIREServerSimulator:
    def __init__(self, trust_domain: str, ca_secret: str = "triaxis_root_ca_secret_key_2026"):
        self.trust_domain = trust_domain
        self.ca_secret = ca_secret
        self.registration_entries: Dict[str, Dict[str, Any]] = {}

    def register_workload(self, entry_id: str, spiffe_path: str, selectors: Dict[str, Any]):
        self.registration_entries[entry_id] = {
            "spiffe_id": SPIFFEID(self.trust_domain, spiffe_path),
            "selectors": selectors
        }

    def _sign(self, data_str: str) -> str:
        return hmac.new(self.ca_secret.encode(), data_str.encode(), hashlib.sha256).hexdigest()

    def issue_svid(self, selectors: Dict[str, Any], ttl_seconds: float = 3600.0, current_time: Optional[float] = None) -> Tuple[Optional[SVID], str]:
        matching_id = None
        for entry in self.registration_entries.values():
            match = True
            for k, v in entry["selectors"].items():
                if selectors.get(k) != v:
                    match = False
                    break
            if match:
                matching_id = entry["spiffe_id"]
                break

        if not matching_id:
            return None, "ATTESTATION_FAILED: No matching registration entry for selectors"

        now = current_time if current_time is not None else time.time()
        payload = {"selectors_matched": selectors}
        sign_str = f"{matching_id.uri()}:{int(now)}:{int(now + ttl_seconds)}"
        signature = self._sign(sign_str)
        svid = SVID(matching_id, now, ttl_seconds, signature, payload)
        return svid, "SUCCESS"

    def verify_svid(self, svid: SVID, current_time: Optional[float] = None) -> bool:
        if svid.is_expired(current_time):
            return False
        sign_str = f"{svid.spiffe_id.uri()}:{int(svid.issued_at)}:{int(svid.expires_at)}"
        expected_sig = self._sign(sign_str)
        return hmac.compare_digest(svid.signature, expected_sig)

class SPIREAgentSimulator:
    def __init__(self, server: SPIREServerSimulator):
        self.server = server
        self.cache: Dict[str, SVID] = {}

    def fetch_workload_svid(self, current_time: Optional[float] = None) -> Tuple[Optional[SVID], str]:
        selectors = WorkloadAttestor.attest_current_process()
        svid, msg = self.server.issue_svid(selectors, current_time=current_time)
        if svid:
            self.cache[svid.spiffe_id.uri()] = svid
        return svid, msg
