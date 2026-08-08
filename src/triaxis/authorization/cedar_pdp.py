"""TRIAXIS v4.0 Cedar Reference PDP Adapter (PI-001).

Classification: CEDAR_LOCAL_REFERENCE_ADAPTER
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contract import AuthorizationRequest
from .decision import AuthorizationDecisionReceipt, DecisionState


class CedarLocalReferencePDP:
    """Cedar Local Reference PDP Adapter invoking cedar-policy-cli via safe subprocess argument arrays."""

    def __init__(
        self,
        *,
        cedar_binary_path: str | Path | None = None,
        policy_filepath: str | Path | None = None,
        entities_filepath: str | Path | None = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        if cedar_binary_path:
            self.binary_path = str(cedar_binary_path)
        else:
            found = shutil.which("cedar") or shutil.which("cedar-policy-cli")
            self.binary_path = found if found else "cedar"
            
        self.policy_filepath = Path(policy_filepath) if policy_filepath else None
        self.entities_filepath = Path(entities_filepath) if entities_filepath else None
        self.timeout_seconds = timeout_seconds
        self.provider_name = "Cedar"
        self.provider_version = "4.12.0"

    def _get_policy_hash(self) -> tuple[int, str]:
        if not self.policy_filepath or not self.policy_filepath.exists():
            return 1, "0" * 64
        h = hashlib.sha256()
        with open(self.policy_filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return 1, h.hexdigest().lower()

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        """Evaluate an AuthorizationRequest against Cedar PDP. Fail closed on any error."""
        now_iso = datetime.now(timezone.utc).isoformat()
        policy_version, policy_hash = self._get_policy_hash()

        # Check binary availability
        if not shutil.which(self.binary_path) and not Path(self.binary_path).exists():
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="CEDAR_BINARY_UNAVAILABLE",
                policy_version=policy_version,
                policy_hash=policy_hash,
                provider=self.provider_name,
                provider_version=self.provider_version,
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=now_iso,
                error_class="FileNotFoundError",
            )

        # Check policy file availability
        if not self.policy_filepath or not self.policy_filepath.exists():
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="CEDAR_POLICY_UNAVAILABLE",
                policy_version=policy_version,
                policy_hash=policy_hash,
                provider=self.provider_name,
                provider_version=self.provider_version,
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=now_iso,
                error_class="PolicyNotFoundError",
            )

        # Policy Pinning Validation
        if request.pinned_policy_sha256 and request.pinned_policy_sha256 != policy_hash:
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="CEDAR_POLICY_HASH_MISMATCH",
                policy_version=policy_version,
                policy_hash=policy_hash,
                provider=self.provider_name,
                provider_version=self.provider_version,
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=now_iso,
                error_class="PolicyHashMismatchError",
            )

        # Construct Cedar entity principals & request
        # Cedar syntax: principal, action, resource, context
        principal_id = f'User::"{request.principal.human_id}"'
        action_id = f'Action::"{request.principal.action}"'
        resource_id = f'Resource::"{request.principal.resource}"'

        # Context JSON passed to Cedar
        context_obj = {
            "agent_instance_id": request.principal.agent_instance_id,
            "delegation_grant_id": request.principal.delegation_grant_id,
            "task_id": request.principal.task_id,
            "risk_class": request.risk_class,
        }
        if request.principal.spiffe_id:
            context_obj["spiffe_id"] = request.principal.spiffe_id

        # Build command array (NO shell interpolation!)
        cmd = [
            self.binary_path,
            "authorize",
            "--policies", str(self.policy_filepath),
            "--principal", principal_id,
            "--action", action_id,
            "--resource", resource_id,
            "--context", json.dumps(context_obj),
        ]
        if self.entities_filepath and self.entities_filepath.exists():
            cmd.extend(["--entities", str(self.entities_filepath)])

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
            exit_code = res.returncode
            stdout_str = res.stdout.strip()

            if exit_code == 0:
                stdout_upper = stdout_str.upper()
                if "ALLOW" in stdout_upper or "ALLOWED" in stdout_upper:
                    return AuthorizationDecisionReceipt(
                        decision=DecisionState.ALLOW,
                        reason_code="CEDAR_DECISION_ALLOW",
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        provider=self.provider_name,
                        provider_version=self.provider_version,
                        request_id=request.principal.request_id,
                        evaluated_principal=request.principal.to_dict(),
                        evaluated_task=request.principal.task_id,
                        evaluated_action=request.principal.action,
                        evaluated_resource=request.principal.resource,
                        evaluation_timestamp_iso=now_iso,
                    )
                elif "DENY" in stdout_upper or "DENIED" in stdout_upper:
                    return AuthorizationDecisionReceipt(
                        decision=DecisionState.DENY,
                        reason_code="CEDAR_DECISION_DENY",
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        provider=self.provider_name,
                        provider_version=self.provider_version,
                        request_id=request.principal.request_id,
                        evaluated_principal=request.principal.to_dict(),
                        evaluated_task=request.principal.task_id,
                        evaluated_action=request.principal.action,
                        evaluated_resource=request.principal.resource,
                        evaluation_timestamp_iso=now_iso,
                    )
                else:
                    return AuthorizationDecisionReceipt(
                        decision=DecisionState.ERROR,
                        reason_code="CEDAR_STDOUT_MALFORMED",
                        policy_version=policy_version,
                        policy_hash=policy_hash,
                        provider=self.provider_name,
                        provider_version=self.provider_version,
                        request_id=request.principal.request_id,
                        evaluated_principal=request.principal.to_dict(),
                        evaluated_task=request.principal.task_id,
                        evaluated_action=request.principal.action,
                        evaluated_resource=request.principal.resource,
                        evaluation_timestamp_iso=now_iso,
                        error_class="MalformedStdoutError",
                    )
            elif exit_code == 2:
                return AuthorizationDecisionReceipt(
                    decision=DecisionState.DENY,
                    reason_code="CEDAR_DECISION_DENY",
                    policy_version=policy_version,
                    policy_hash=policy_hash,
                    provider=self.provider_name,
                    provider_version=self.provider_version,
                    request_id=request.principal.request_id,
                    evaluated_principal=request.principal.to_dict(),
                    evaluated_task=request.principal.task_id,
                    evaluated_action=request.principal.action,
                    evaluated_resource=request.principal.resource,
                    evaluation_timestamp_iso=now_iso,
                )
            else:
                return AuthorizationDecisionReceipt(
                    decision=DecisionState.ERROR,
                    reason_code="CEDAR_PROCESS_ERROR",
                    policy_version=policy_version,
                    policy_hash=policy_hash,
                    provider=self.provider_name,
                    provider_version=self.provider_version,
                    request_id=request.principal.request_id,
                    evaluated_principal=request.principal.to_dict(),
                    evaluated_task=request.principal.task_id,
                    evaluated_action=request.principal.action,
                    evaluated_resource=request.principal.resource,
                    evaluation_timestamp_iso=now_iso,
                    error_class=f"ProcessExitCode_{exit_code}",
                )

        except subprocess.TimeoutExpired:
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="CEDAR_EVALUATION_TIMEOUT",
                policy_version=policy_version,
                policy_hash=policy_hash,
                provider=self.provider_name,
                provider_version=self.provider_version,
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=now_iso,
                error_class="TimeoutExpired",
            )
        except Exception as exc:
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="CEDAR_EVALUATION_EXCEPTION",
                policy_version=policy_version,
                policy_hash=policy_hash,
                provider=self.provider_name,
                provider_version=self.provider_version,
                request_id=request.principal.request_id,
                evaluated_principal=request.principal.to_dict(),
                evaluated_task=request.principal.task_id,
                evaluated_action=request.principal.action,
                evaluated_resource=request.principal.resource,
                evaluation_timestamp_iso=now_iso,
                error_class=type(exc).__name__,
            )
