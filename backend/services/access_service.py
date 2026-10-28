"""
ZeroTrace - Scoped Temporary Demonstration Access Credential Service
---------------------------------------------------------------------
Controls access to the software-controlled test environment.
Enforces cryptographically secure generation, SHA-256 verifier storage,
time-limited expiry, scope validation, and explicit revocation.

IMPORTANT SAFETY NOTICE:
TEMPORARY DEMO ENVIRONMENT CREDENTIAL — NOT A HARDWARE JTAG PASSWORD
This credential grants access only to the software simulation environment.
It CANNOT unlock raw physical JTAG, bypass silicon eFuses, or disable Secure Boot.
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, List, Tuple
import logging

from backend.schemas.models import CredentialResponse
from backend.services.event_service import event_service

logger = logging.getLogger("ZeroTraceAccessService")

class AccessService:
    def __init__(self):
        # Maps credential_id -> metadata dict containing hashed_verifier (NEVER plaintext)
        self._credentials: Dict[str, dict] = {}

    def issue_credential(
        self,
        environment: str = "zerotrace-sim-env",
        scope: Optional[List[str]] = None,
        lifetime_seconds: int = 600,
        operator: str = "red_team_operator"
    ) -> CredentialResponse:
        """
        Generates a new temporary demo credential using secrets.token_urlsafe.
        Stores only the SHA-256 hash in memory.
        Returns the plaintext token ONLY ONCE in this response.
        """
        if scope is None:
            scope = ["test:run", "ota:stage", "fault:inject", "debug:audit", "dataset:create", "dataset:sanitize"]

        # Cryptographically secure random token (256-bit entropy)
        raw_secret = f"zt_{secrets.token_urlsafe(32)}"
        hashed_secret = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

        cred_id = f"CRED-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=lifetime_seconds)

        record = {
            "credential_id": cred_id,
            "hashed_verifier": hashed_secret,
            "environment": environment,
            "scope": scope,
            "permitted_operations": scope,
            "created_at": now.isoformat() + "Z",
            "expires_at": expires_at.isoformat() + "Z",
            "lifetime_seconds": lifetime_seconds,
            "revoked": False,
            "operator": operator
        }

        self._credentials[cred_id] = record

        # Emit audit event (WITHOUT the secret!)
        asyncio_loop_or_task = None
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(event_service.publish_event(
                    layer="Access Management",
                    source="access_service",
                    event_type="CREDENTIAL_ISSUED",
                    severity="INFO",
                    status="PASS",
                    credential_id=cred_id,
                    evidence_level="SOFTWARE_VERIFIED",
                    message=f"Temporary demo credential {cred_id} issued for environment '{environment}' (TTL: {lifetime_seconds}s).",
                    details={"scope": scope, "environment": environment, "expires_at": record["expires_at"]}
                ))
        except Exception as e:
            logger.warning(f"Could not async log credential event: {e}")

        return CredentialResponse(
            credential_id=cred_id,
            plaintext_secret=raw_secret,  # Returned only once to operator
            environment=environment,
            scope=scope,
            permitted_operations=scope,
            created_at=record["created_at"],
            expires_at=record["expires_at"],
            lifetime_seconds=lifetime_seconds,
            revoked=False
        )

    def verify_credential(
        self,
        credential_id: str,
        plaintext_token: str,
        required_operation: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Validates token against stored SHA-256 verifier, checking expiry and revocation.
        """
        if not credential_id or credential_id not in self._credentials:
            return False, "Unknown credential ID"

        cred = self._credentials[credential_id]

        if cred["revoked"]:
            return False, "Credential has been revoked"

        # Check expiry
        exp = datetime.fromisoformat(cred["expires_at"].replace("Z", ""))
        if datetime.now(timezone.utc) > exp:
            return False, "Credential has expired"

        # Hash and compare using constant-time comparison
        calc_hash = hashlib.sha256(plaintext_token.encode("utf-8")).hexdigest()
        if not secrets.compare_digest(calc_hash, cred["hashed_verifier"]):
            return False, "Invalid credential authentication token"

        # Scope validation
        if required_operation and required_operation not in cred["permitted_operations"]:
            return False, f"Operation '{required_operation}' not permitted by credential scope"

        return True, "Valid"

    def revoke_credential(self, credential_id: str, reason: str = "Operator revoked") -> Tuple[bool, str]:
        """Revokes an existing credential immediately."""
        if credential_id not in self._credentials:
            return False, "Credential not found"

        self._credentials[credential_id]["revoked"] = True

        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(event_service.publish_event(
                    layer="Access Management",
                    source="access_service",
                    event_type="CREDENTIAL_REVOKED",
                    severity="MEDIUM",
                    status="REVOKED",
                    credential_id=credential_id,
                    evidence_level="SOFTWARE_VERIFIED",
                    message=f"Credential {credential_id} revoked by operator. Reason: {reason}",
                    details={"reason": reason}
                ))
        except Exception:
            pass

        return True, "Revoked successfully"

    def get_credential_status(self, credential_id: str) -> Optional[dict]:
        """Returns metadata for a credential (NEVER plaintext or hashes)."""
        if credential_id not in self._credentials:
            return None
        c = self._credentials[credential_id]
        exp = datetime.fromisoformat(c["expires_at"].replace("Z", ""))
        now = datetime.now(timezone.utc)
        remaining = max(0, int((exp - now).total_seconds())) if not c["revoked"] else 0

        return {
            "credential_id": c["credential_id"],
            "environment": c["environment"],
            "scope": c["scope"],
            "created_at": c["created_at"],
            "expires_at": c["expires_at"],
            "lifetime_seconds": c["lifetime_seconds"],
            "remaining_seconds": remaining,
            "revoked": c["revoked"],
            "expired": now > exp,
            "active": (not c["revoked"]) and (now <= exp),
            "label": "TEMPORARY DEMO ENVIRONMENT CREDENTIAL — NOT A HARDWARE JTAG PASSWORD"
        }

    def list_active_credentials(self) -> List[dict]:
        results = []
        for cid in list(self._credentials.keys()):
            status = self.get_credential_status(cid)
            if status:
                results.append(status)
        return results

# Singleton instance
access_service = AccessService()
