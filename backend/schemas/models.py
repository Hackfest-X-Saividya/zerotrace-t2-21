"""
ZeroTrace - Unified Pydantic Schemas & Data Contracts
------------------------------------------------------
Covers shared events, audit logs, temporary access credentials,
hardware device states, and layer-specific data models.
"""

from typing import Dict, List, Optional, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field

# Severity levels for security events
SeverityLevel = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Evidence levels as required by ZeroTrace governance
EvidenceLevel = Literal["SIMULATED", "REPORTED", "SOFTWARE_VERIFIED", "HARDWARE_VERIFIED", "INCONCLUSIVE"]

# Event Status
EventStatus = Literal["PASS", "FAIL", "ALERT", "BLOCKED", "REVOKED", "INCONCLUSIVE", "INFO"]

class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    test_id: Optional[str] = None
    layer: str
    source: str
    event_type: str
    severity: SeverityLevel
    status: EventStatus
    device_id: Optional[str] = None
    dataset_id: Optional[str] = None
    credential_id: Optional[str] = None
    evidence_level: EvidenceLevel
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: str

class IssueCredentialRequest(BaseModel):
    environment: str = "zerotrace-sim-env"
    scope: List[str] = Field(default_factory=lambda: ["test:run", "ota:stage", "fault:inject", "debug:audit"])
    lifetime_seconds: int = Field(default=600, ge=60, le=3600)
    operator: str = "red_team_operator"

class CredentialResponse(BaseModel):
    credential_id: str
    plaintext_secret: Optional[str] = None  # ONLY returned upon initial issuance
    environment: str
    scope: List[str]
    permitted_operations: List[str]
    created_at: str
    expires_at: str
    lifetime_seconds: int
    revoked: bool
    label: str = "TEMPORARY DEMO ENVIRONMENT CREDENTIAL — NOT A HARDWARE JTAG PASSWORD"
    warning: str = "This credential is temporary, scoped to software simulation, and cannot bypass physical hardware security."

class RevokeCredentialRequest(BaseModel):
    credential_id: str
    reason: str = "Operator revoked credential"

class VerifyCredentialRequest(BaseModel):
    credential_id: str
    token: str
    required_scope: str

# Layer 1 Models
class OTAUpdateRequest(BaseModel):
    scenario: str = "valid"  # 'valid', 'tampered', 'invalid_tag', 'replay', 'downgrade', 'bad_metadata', 'interrupted'
    target_device: str = "hardened"  # 'baseline' or 'hardened'
    credential_id: Optional[str] = None
    credential_token: Optional[str] = None

# Layer 2 Models
class FaultInjectionRequest(BaseModel):
    scenario: str = "consistent"  # 'consistent', 'inconsistent', 'fault_pulse', 'watchdog_reset', 'missing_telemetry', 'safe_recovery', 'recovery_verify', 'repeated_anomaly', or L2_01..L2_11
    target_device: str = "hardened"
    execution_mode: Optional[str] = "demo"
    credential_id: Optional[str] = None
    credential_token: Optional[str] = None

# Layer 3 Models
class SiliconAuditRequest(BaseModel):
    scenario: str = "read_only_audit"  # 'read_only_audit', 'policy_violation_sim', 'unauthorized_access'
    target_device: str = "hardened"
    credential_id: Optional[str] = None
    credential_token: Optional[str] = None

# Layer 4 Models
class CreateDatasetRequest(BaseModel):
    name: str = "Telemetry_Vault_Record_01"
    size_bytes: int = Field(default=256, ge=16, le=16384)

class SanitizeDatasetRequest(BaseModel):
    dataset_id: str
    confirm: bool = False
    authorization_token: Optional[str] = None
    credential_id: Optional[str] = None

class DecryptTestRequest(BaseModel):
    dataset_id: str
    tamper_ciphertext: bool = False

# Blue Team Verifier Models
class BlueTeamFinding(BaseModel):
    finding_id: str
    timestamp: str
    test_id: Optional[str]
    layer: str
    severity: SeverityLevel
    verdict: str  # 'DEFENSE_SUCCESS', 'WEAKNESS_OBSERVED', 'SECURITY_BREACH_PREVENTED', 'ATTACK_REJECTED', 'INCONCLUSIVE'
    evidence_level: EvidenceLevel
    threat_description: str
    metric_observed: str
    mitigation_action: str
    verified_independent: bool
    correlation_id: str

# Red Team Scenario Specification
class RedTeamScenario(BaseModel):
    id: str
    layer: str
    name: str
    description: str
    objective: str
    expected_result: str
    requires_credential: bool
    csf_function: str
    csf_category: str
    evidence_level: EvidenceLevel
