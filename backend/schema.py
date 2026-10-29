"""
ZeroTrace — Validated Data Schemas (Pydantic v2)
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class SecurityProblemDef(BaseModel):
    problem_id: str = Field(..., description="Unique Problem ID e.g. SEC-L1-01")
    layer: int = Field(..., ge=1, le=4, description="Layer number 1 to 4")
    title: str
    security_objective: str
    threat_failure_mode: str
    countermeasure: str
    implementation_module: str
    test_id: str
    research_citations: List[str]
    evidence_type: str
    limitation_notes: str
    default_status: str = "NOT_TESTED"

class EventRecord(BaseModel):
    event_id: str
    run_id: str
    test_id: str
    timestamp_utc: str
    device_timestamp_us: Optional[int] = None
    elapsed_ms: float
    layer: int
    device: str
    scenario: str
    event_type: str
    observed_state: str
    requested_action: str
    defense_action: str
    outcome: str  # PASS, FAIL, INCONCLUSIVE, NOT_TESTED
    risk_level: str  # LOW, MEDIUM, HIGH
    risk_rationale: str
    evidence_level: str  # RESEARCH_VALIDATED, HARDWARE_MEASURED, SIMULATED
    waveform_source: str  # PHYSICAL_MEASUREMENT, DEVICE_TELEMETRY, SIMULATED — NOT MEASURED
    signal_name: Optional[str] = "VCC_SUPPLY_RAIL"
    value: Optional[float] = None
    unit: Optional[str] = "V"
    sample_rate_hz: Optional[int] = None
    notes: Optional[str] = ""

class TelemetryFrame(BaseModel):
    timestamp_utc: str
    elapsed_ms: float
    source_mode: str  # PHYSICAL_MEASUREMENT, DEVICE_TELEMETRY, SIMULATED — NOT MEASURED
    voltage: float
    current_ma: float
    trigger_state: int
    active_scenario: Optional[str] = None
    recent_events: List[EventRecord] = []

class WaveformBatch(BaseModel):
    run_id: str
    test_id: str
    source_mode: str
    signal_name: str
    unit: str
    sample_rate_hz: int
    time_ms: List[float]
    voltage_samples: List[float]
    trigger_samples: List[int]
    events: List[EventRecord]

class MetricsSnapshot(BaseModel):
    layer: int
    executed_tests: int
    successful_mitigations: int
    failed_tests: int
    inconclusive_tests: int
    detection_rate_pct: float
    containment_rate_pct: float
    mean_detection_latency_ms: float
    mean_defense_latency_ms: float
    mean_containment_latency_ms: float
    mean_recovery_duration_ms: float

class RunConfig(BaseModel):
    run_id: str
    target_layer: int
    scenario_ids: List[str]
    hardware_mode: str = "AUTO"  # AUTO, PHYSICAL, SIMULATED
    injected_fault_type: Optional[str] = None
    operator: str = "ZeroTrace Automated Test System"

