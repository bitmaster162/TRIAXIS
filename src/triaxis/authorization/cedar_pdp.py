"""TRIAXIS v4.0 Cedar Local Reference PDP Adapter (PI-001 R2).

Executes Cedar policy authorization via official Cedar CLI (`cedar authorize`).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contract import AuthorizationRequest
from .decision import AuthorizationDecisionReceipt, DecisionState


class CedarLocalReferencePDP:
    """Reference PDP adapter invoking official Cedar CLI in a local subprocess."""

    def __init__(
        self,
        cedar_binary_path: str = "cedar",
        policy_filepath: str | Path | None = None,
        entities_filepath: str | Path | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.binary_path = cedar_binary_path
        self.policy_filepath = Path(policy_filepath) if policy_filepath else None
        self.entities_filepath = Path(entities_filepath) if entities_filepath else None
        self.timeout_seconds = timeout_seconds
        self.provider_name = "Cedar"
        self._provider_version: str | None = None
        self._binary_sha256: str | None = None
        self._cedar_ready: bool = False
        self._inspect_environment()

    def _resolve_binary(self) -> str | None:
        if shutil.which(self.binary_path):
            return self.binary_path
        if Path(self.binary_path).exists():
            return self.binary_path
        wsl_cedar = "/home/bit/.cargo/bin/cedar"
        if Path(wsl_cedar).exists():
            return wsl_cedar
        if os.name == "nt":
            try:
                res = subprocess.run(["wsl", "-e", "test", "-x", wsl_cedar], capture_output=True)
                if res.returncode == 0:
                    return wsl_cedar
            except Exception:
                pass
        return None

    def _inspect_environment(self) -> None:
        resolved = self._resolve_binary()
        if not resolved:
            self._cedar_ready = False
            self._provider_version = "CEDAR_UNAVAILABLE"
            self._binary_sha256 = "0" * 64
            return

        try:
            if os.name == "nt" and resolved.startswith("/"):
                cmd = ["wsl", "-e", resolved, "--version"]
                sha_cmd = ["wsl", "-e", "sha256sum", resolved]
            else:
                cmd = [resolved, "--version"]
                sha_cmd = None

            v_res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
            if v_res.returncode == 0 and v_res.stdout.strip():
                self._provider_version = v_res.stdout.strip()
                self._cedar_ready = True
            else:
                self._provider_version = "CEDAR_VERSION_UNKNOWN"
                self._cedar_ready = False

            if sha_cmd:
                s_res = subprocess.run(sha_cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
                if s_res.returncode == 0:
                    self._binary_sha256 = s_res.stdout.split()[0].lower()
                else:
                    self._binary_sha256 = "0" * 64
            elif Path(resolved).exists():
                h = hashlib.sha256()
                with open(resolved, "rb") as f:
                    while chunk := f.read(8192):
                        h.update(chunk)
                self._binary_sha256 = h.hexdigest().lower()
            else:
                self._binary_sha256 = "0" * 64
        except Exception:
            self._cedar_ready = False
            self._provider_version = "CEDAR_INSPECTION_FAILED"
            self._binary_sha256 = "0" * 64

    @property
    def provider_version(self) -> str:
        return self._provider_version or "CEDAR_UNAVAILABLE"

    @property
    def binary_sha256(self) -> str:
        return self._binary_sha256 or ("0" * 64)

    @property
    def cedar_ready(self) -> bool:
        return self._cedar_ready

    def get_cedar_policy_hash(self) -> str:
        if not self.policy_filepath or not self.policy_filepath.exists():
            return "0" * 64
        h = hashlib.sha256()
        with open(self.policy_filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest().lower()

    def evaluate(self, request: AuthorizationRequest) -> AuthorizationDecisionReceipt:
        """Evaluate an AuthorizationRequest against Cedar PDP. Fail closed on any error."""
        now_iso = datetime.now(timezone.utc).isoformat()
        cedar_policy_hash = self.get_cedar_policy_hash()
        triaxis_policy_hash = request.triaxis_policy_sha256 or ("0" * 64)

        # Check binary availability
        resolved_bin = self._resolve_binary()
        if not resolved_bin or not self._cedar_ready:
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="CEDAR_BINARY_UNAVAILABLE",
                policy_version=1,
                triaxis_policy_sha256=triaxis_policy_hash,
                cedar_policy_sha256=cedar_policy_hash,
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
                policy_version=1,
                triaxis_policy_sha256=triaxis_policy_hash,
                cedar_policy_sha256=cedar_policy_hash,
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

        # Policy Pinning Validation against Cedar Policy SHA
        if request.cedar_policy_sha256 and request.cedar_policy_sha256 != cedar_policy_hash:
            return AuthorizationDecisionReceipt(
                decision=DecisionState.ERROR,
                reason_code="CEDAR_POLICY_HASH_MISMATCH",
                policy_version=1,
                triaxis_policy_sha256=triaxis_policy_hash,
                cedar_policy_sha256=cedar_policy_hash,
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

        # Prepare Cedar arguments
        principal_id = f'User::"{request.principal.human_id}"'
        action_id = f'Action::"{request.principal.action}"'
        resource_id = f'Resource::"{request.principal.resource}"'

        context_obj = {
            "agent_instance_id": request.principal.agent_instance_id,
            "delegation_grant_id": request.principal.delegation_grant_id,
            "task_id": request.principal.task_id,
            "risk_class": request.risk_class,
        }
        if request.principal.spiffe_id:
            context_obj["spiffe_id"] = request.principal.spiffe_id

        # Write context JSON to temp file
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as ctx_file:
            json.dump(context_obj, ctx_file)
            ctx_path = ctx_file.name

        # Ensure entities file exists
        if self.entities_filepath and self.entities_filepath.exists():
            entities_path = str(self.entities_filepath)
            temp_entities = None
        else:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as ent_file:
                json.dump([], ent_file)
                entities_path = ent_file.name
                temp_entities = entities_path

        # Linux path conversion if running WSL
        if os.name == "nt" and resolved_bin.startswith("/"):
            pol_path_wsl = str(self.policy_filepath).replace("c:\\", "/mnt/c/").replace("C:\\", "/mnt/c/").replace("\\", "/")
            ctx_path_wsl = ctx_path.replace("C:\\", "/mnt/c/").replace("c:\\", "/mnt/c/").replace("\\", "/")
            ent_path_wsl = entities_path.replace("C:\\", "/mnt/c/").replace("c:\\", "/mnt/c/").replace("\\", "/")

            cmd = [
                "wsl", "-e", resolved_bin, "authorize",
                "--policies", pol_path_wsl,
                "--entities", ent_path_wsl,
                "--context", ctx_path_wsl,
                "--principal", principal_id,
                "--action", action_id,
                "--resource", resource_id,
            ]
        else:
            cmd = [
                resolved_bin, "authorize",
                "--policies", str(self.policy_filepath),
                "--entities", entities_path,
                "--context", ctx_path,
                "--principal", principal_id,
                "--action", action_id,
                "--resource", resource_id,
            ]

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
            stderr_str = res.stderr.strip()

            # Strict Cedar Response Parser (Section 3)
            if exit_code == 0:
                if stdout_str == "ALLOW":
                    return AuthorizationDecisionReceipt(
                        decision=DecisionState.ALLOW,
                        reason_code="CEDAR_DECISION_ALLOW",
                        policy_version=1,
                        triaxis_policy_sha256=triaxis_policy_hash,
                        cedar_policy_sha256=cedar_policy_hash,
                        provider=self.provider_name,
                        provider_version=self.provider_version,
                        request_id=request.principal.request_id,
                        evaluated_principal=request.principal.to_dict(),
                        evaluated_task=request.principal.task_id,
                        evaluated_action=request.principal.action,
                        evaluated_resource=request.principal.resource,
                        evaluation_timestamp_iso=now_iso,
                    )
                elif stdout_str == "DENY":
                    return AuthorizationDecisionReceipt(
                        decision=DecisionState.DENY,
                        reason_code="CEDAR_DECISION_DENY",
                        policy_version=1,
                        triaxis_policy_sha256=triaxis_policy_hash,
                        cedar_policy_sha256=cedar_policy_hash,
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
                    # Garbage or non-exact ALLOW stdout on exit 0
                    return AuthorizationDecisionReceipt(
                        decision=DecisionState.ERROR,
                        reason_code="CEDAR_STDOUT_MALFORMED",
                        policy_version=1,
                        triaxis_policy_sha256=triaxis_policy_hash,
                        cedar_policy_sha256=cedar_policy_hash,
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
                # DENY exit code
                return AuthorizationDecisionReceipt(
                    decision=DecisionState.DENY,
                    reason_code="CEDAR_DECISION_DENY",
                    policy_version=1,
                    triaxis_policy_sha256=triaxis_policy_hash,
                    cedar_policy_sha256=cedar_policy_hash,
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
                    policy_version=1,
                    triaxis_policy_sha256=triaxis_policy_hash,
                    cedar_policy_sha256=cedar_policy_hash,
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
                reason_code="CEDAR_PROCESS_TIMEOUT",
                policy_version=1,
                triaxis_policy_sha256=triaxis_policy_hash,
                cedar_policy_sha256=cedar_policy_hash,
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
                reason_code="CEDAR_EXECUTION_EXCEPTION",
                policy_version=1,
                triaxis_policy_sha256=triaxis_policy_hash,
                cedar_policy_sha256=cedar_policy_hash,
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
        finally:
            if os.path.exists(ctx_path):
                os.remove(ctx_path)
            if temp_entities and os.path.exists(temp_entities):
                os.remove(temp_entities)
