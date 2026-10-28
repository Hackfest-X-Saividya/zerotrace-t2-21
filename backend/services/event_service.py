"""
ZeroTrace - Centralized Shared Event & Audit Service
-----------------------------------------------------
Handles event bus publishing, audit trail persistence,
SSE broadcasting, correlation tracking, and sanitization of secrets.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from collections import deque
from typing import List, Dict, Optional, Any
import logging

from backend.schemas.models import SecurityEvent, BlueTeamFinding

logger = logging.getLogger("ZeroTraceEventService")

class EventService:
    def __init__(self, max_history: int = 1000):
        self.events: deque = deque(maxlen=max_history)
        self.audit_log: deque = deque(maxlen=max_history)
        self.findings: deque = deque(maxlen=500)
        self.sse_queues: List[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    def sanitize_payload(self, data: Any) -> Any:
        """
        Defense-in-depth sanitizer to ensure no keys, passwords, or plaintext
        tokens are ever recorded or broadcast through events or audit trails.
        """
        forbidden_keys = {"secret", "plaintext_secret", "key_bytes", "aes_key", "hmac_key", "raw_data", "password"}
        if isinstance(data, dict):
            clean = {}
            for k, v in data.items():
                if any(fk in k.lower() for fk in forbidden_keys):
                    clean[k] = "[REDACTED_BY_SECURITY_POLICY]"
                else:
                    clean[k] = self.sanitize_payload(v)
            return clean
        elif isinstance(data, list):
            return [self.sanitize_payload(item) for item in data]
        return data

    async def publish_event(
        self,
        layer: str,
        source: str,
        event_type: str,
        severity: str,
        status: str,
        message: str,
        evidence_level: str = "SOFTWARE_VERIFIED",
        test_id: Optional[str] = None,
        device_id: Optional[str] = None,
        dataset_id: Optional[str] = None,
        credential_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ) -> SecurityEvent:
        """Publishes a structured SecurityEvent across ZeroTrace."""
        cid = correlation_id or str(uuid.uuid4())
        eid = f"evt_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        clean_details = self.sanitize_payload(details or {})

        # Normalize evidence_level
        s_ev = str(evidence_level or "SOFTWARE_VERIFIED").upper().replace("-", "_")
        if "SIMULAT" in s_ev:
            norm_ev = "SIMULATED"
        elif "HARDWARE" in s_ev:
            norm_ev = "HARDWARE_VERIFIED"
        elif "REPORT" in s_ev:
            norm_ev = "REPORTED"
        elif "SOFTWARE" in s_ev or "LEVEL" in s_ev:
            norm_ev = "SOFTWARE_VERIFIED"
        else:
            norm_ev = "INCONCLUSIVE"

        # Normalize severity
        s_sev = str(severity or "INFO").upper()
        if s_sev not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            s_sev = "INFO"

        # Normalize status
        s_stat = str(status or "INFO").upper()
        if s_stat not in {"PASS", "FAIL", "ALERT", "BLOCKED", "REVOKED", "INCONCLUSIVE", "INFO"}:
            if "PASS" in s_stat:
                s_stat = "PASS"
            elif "FAIL" in s_stat or "REJECT" in s_stat:
                s_stat = "FAIL"
            else:
                s_stat = "INFO"

        event = SecurityEvent(
            event_id=eid,
            timestamp=now,
            test_id=test_id,
            layer=layer,
            source=source,
            event_type=event_type,
            severity=s_sev,  # type: ignore
            status=s_stat,  # type: ignore
            device_id=device_id,
            dataset_id=dataset_id,
            credential_id=credential_id,
            evidence_level=norm_ev,  # type: ignore
            message=message,
            details=clean_details,
            correlation_id=cid
        )

        async with self._lock:
            self.events.append(event)
            self.audit_log.append({
                "audit_id": f"aud_{uuid.uuid4().hex[:8]}",
                "timestamp": now,
                "event_id": eid,
                "layer": layer,
                "source": source,
                "action": event_type,
                "status": status,
                "severity": severity,
                "evidence_level": evidence_level,
                "summary": message,
                "correlation_id": cid
            })

        # Broadcast via SSE
        await self.broadcast("security_event", event.model_dump())
        return event

    async def record_finding(self, finding: BlueTeamFinding) -> None:
        """Records an authoritative Blue Team defensive finding."""
        async with self._lock:
            self.findings.append(finding)
        await self.broadcast("blue_team_finding", finding.model_dump())

    async def broadcast(self, payload_type: str, data: Any):
        msg = {
            "type": payload_type,
            "payload": data,
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        }
        encoded = json.dumps(msg)
        dead_queues = []
        for q in self.sse_queues:
            try:
                q.put_nowait(encoded)
            except Exception:
                dead_queues.append(q)
        for dead in dead_queues:
            if dead in self.sse_queues:
                self.sse_queues.remove(dead)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.sse_queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        if q in self.sse_queues:
            self.sse_queues.remove(q)

    def get_events(
        self,
        limit: int = 100,
        layer: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        evidence_level: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        results = []
        for ev in reversed(self.events):
            if layer and layer.lower() not in ev.layer.lower():
                continue
            if severity and ev.severity.upper() != severity.upper():
                continue
            if status and ev.status.upper() != status.upper():
                continue
            if evidence_level and ev.evidence_level.upper() != evidence_level.upper():
                continue
            results.append(ev.model_dump())
            if len(results) >= limit:
                break
        return results

    def get_audit_trail(self, limit: int = 100) -> List[Dict[str, Any]]:
        return list(reversed(self.audit_log))[:limit]

    def get_findings(self, limit: int = 100) -> List[Dict[str, Any]]:
        return [f.model_dump() for f in list(reversed(self.findings))[:limit]]

    def clear(self):
        self.events.clear()
        self.audit_log.clear()
        self.findings.clear()

# Singleton instance
event_service = EventService()
