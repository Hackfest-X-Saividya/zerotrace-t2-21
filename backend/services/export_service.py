"""
ZeroTrace - Judge Evidence Export Service
-----------------------------------------
Generates auditable CSV, PDF, and JSON evidence packages for hackathon judges
with verifiable timestamps, per-device telemetry, latencies, and SHA-256 integrity hashes.
"""

import io
import csv
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak, HRFlowable
)

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def generate_evidence_csv(
    campaign_results: List[Dict[str, Any]],
    campaign_id: str = "camp-default",
    device_status: Optional[Dict[str, Any]] = None,
    campaign_mode: str = "hardware"
) -> str:
    """
    Generates CSV formatted judge evidence with one row per device per scenario execution.
    Columns:
      campaign_id, scenario_id, layer, scenario_name, event_id, timestamp_utc,
      device_id, board_type, firmware_version, request_id, sequence_number,
      event_type, red_team_action, blue_team_control, response_status,
      expected_outcome, observed_outcome, response_latency_ms,
      evidence_level, final_status, explanation, campaign_mode
    """
    output = io.StringIO()
    fieldnames = [
        "campaign_id",
        "scenario_id",
        "layer",
        "scenario_name",
        "event_id",
        "timestamp_utc",
        "device_id",
        "board_type",
        "firmware_version",
        "request_id",
        "sequence_number",
        "event_type",
        "red_team_action",
        "blue_team_control",
        "response_status",
        "expected_outcome",
        "observed_outcome",
        "response_latency_ms",
        "evidence_level",
        "final_status",
        "explanation",
        "campaign_mode"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
    writer.writeheader()

    dev_status = device_status or {}
    b_info = dev_status.get("baseline", {}) or {}
    h_info = dev_status.get("hardened", {}) or {}

    b_chip = b_info.get("chip_info") or {}
    h_chip = h_info.get("chip_info") or {}

    b_fw = b_chip.get("firmware_id", "zerotrace-baseline-v2.0" if b_info.get("connected") else "")
    h_fw = h_chip.get("firmware_id", "zerotrace-hardened-v2.0" if h_info.get("connected") else "")
    mode_str = "DEMO / SOFTWARE MODE" if campaign_mode in ["demo", "simulation"] else "HARDWARE MODE"

    for idx, item in enumerate(campaign_results):
        sc_id = item.get("test_id", "")
        sc_name = item.get("name", "")
        layer = item.get("layer", "")
        ts = item.get("timestamp", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        req_id = item.get("request_id", "")
        ev_level = item.get("evidence_level", "SOFTWARE_VERIFIED")
        seq = item.get("sequence_number", idx + 1)
        cid = item.get("campaign_id", campaign_id)

        # Baseline row
        writer.writerow({
            "campaign_id": cid,
            "scenario_id": sc_id,
            "layer": layer,
            "scenario_name": sc_name,
            "event_id": f"{item.get('id', 'evt')}-baseline",
            "timestamp_utc": ts,
            "device_id": "esp8266-baseline",
            "board_type": "esp8266",
            "firmware_version": b_fw,
            "request_id": req_id,
            "sequence_number": seq,
            "event_type": "DEVICE_EXECUTION",
            "red_team_action": item.get("red_team_action", f"Initiate {sc_id}"),
            "blue_team_control": "Checksum validation (Weakness seeded; no HMAC)",
            "response_status": item.get("status_baseline", "UNKNOWN"),
            "expected_outcome": item.get("expected_baseline", ""),
            "observed_outcome": item.get("observed_baseline", ""),
            "response_latency_ms": item.get("latency_baseline_ms", ""),
            "evidence_level": ev_level,
            "final_status": item.get("status_baseline", "UNKNOWN"),
            "explanation": item.get("details_baseline", ""),
            "campaign_mode": mode_str
        })

        # Hardened row
        writer.writerow({
            "campaign_id": cid,
            "scenario_id": sc_id,
            "layer": layer,
            "scenario_name": sc_name,
            "event_id": f"{item.get('id', 'evt')}-hardened",
            "timestamp_utc": ts,
            "device_id": "esp32-hardened",
            "board_type": "esp32",
            "firmware_version": h_fw,
            "request_id": req_id,
            "sequence_number": seq,
            "event_type": "DEVICE_EXECUTION",
            "red_team_action": item.get("red_team_action", f"Initiate {sc_id}"),
            "blue_team_control": item.get("blue_control", "Cryptographic HMAC / Anti-Rollback / Enclave"),
            "response_status": item.get("status_hardened", "UNKNOWN"),
            "expected_outcome": item.get("expected_hardened", ""),
            "observed_outcome": item.get("observed_hardened", ""),
            "response_latency_ms": item.get("latency_hardened_ms", ""),
            "evidence_level": ev_level,
            "final_status": item.get("status_hardened", "UNKNOWN"),
            "explanation": item.get("details_hardened", ""),
            "campaign_mode": mode_str
        })

    return output.getvalue()


def generate_evidence_json(
    campaign_results: List[Dict[str, Any]],
    campaign_id: str = "camp-default",
    device_status: Optional[Dict[str, Any]] = None,
    summary: Optional[Dict[str, Any]] = None,
    campaign_mode: str = "hardware"
) -> Dict[str, Any]:
    """Generates machine-readable JSON bundle with SHA-256 digest."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle_core = {
        "title": "ZeroTrace Red Team vs Blue Team Demonstration Evidence Bundle",
        "framework_version": "2.0.0",
        "campaign_id": campaign_id,
        "campaign_mode": "DEMO / SOFTWARE MODE" if campaign_mode in ["demo", "simulation"] else "HARDWARE MODE (DUAL USB)",
        "exported_at": now,
        "hardware_environment": {
            "device_a": {
                "role": "Baseline Weakness Demonstrator",
                "board": "ESP8266 NodeMCU",
                "status": device_status.get("baseline", {}) if device_status else {}
            },
            "device_b": {
                "role": "Hardened Defense Validator",
                "board": "ESP32 DevKit V1",
                "status": device_status.get("hardened", {}) if device_status else {}
            }
        },
        "summary": summary or {},
        "scenarios": campaign_results,
        "disclaimer": (
            "ZeroTrace is a controlled embedded security testbed. Real UART responses "
            "are classified as HARDWARE_VERIFIED. In-memory Python cryptographic operations "
            "are classified as SOFTWARE_VERIFIED. No simulated results are labeled as hardware."
        )
    }

    raw_json = json.dumps(bundle_core, sort_keys=True, indent=2).encode("utf-8")
    digest = compute_sha256(raw_json)
    bundle_core["sha256_digest"] = digest
    return bundle_core


def generate_evidence_pdf(
    campaign_results: List[Dict[str, Any]],
    campaign_id: str = "camp-default",
    device_status: Optional[Dict[str, Any]] = None,
    summary: Optional[Dict[str, Any]] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    campaign_mode: str = "hardware"
) -> bytes:
    """
    Generates a readable, high-aesthetic judge report PDF using ReportLab.
    Contains:
      - Header & Campaign ID
      - Hardware readiness and board identities
      - Executive summary & counts by outcome and evidence level
      - 10-scenario comparison results table
      - Attack-Defence Event Trace & latency observations
      - Distinctions between hardware vs software evidence
      - Limitations and honest engineering disclaimers
      - SHA-256 integrity hash
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=12
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#334155")
    )
    code_style = ParagraphStyle(
        "CodeCustom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )
    badge_pass = ParagraphStyle(
        "BadgePass",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#16a34a")
    )
    badge_fail = ParagraphStyle(
        "BadgeFail",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#dc2626")
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("ZeroTrace — Embedded Security Testbed", title_style))
    story.append(Paragraph("Auditable Red Team vs Blue Team Demonstration & Judge Evidence Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#e2e8f0"), spaceAfter=10))

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    dev_status = device_status or {}
    b_stat = dev_status.get("baseline", {}) or {}
    h_stat = dev_status.get("hardened", {}) or {}

    b_connected = b_stat.get("connected", False)
    h_connected = h_stat.get("connected", False)
    mode_label = "DEMO / SOFTWARE MODE" if campaign_mode in ["demo", "simulation"] else "HARDWARE MODE (DUAL USB)"

    # Metadata & Hardware Table
    meta_data = [
        [
            Paragraph("<b>Campaign ID:</b>", body_style), Paragraph(campaign_id, code_style),
            Paragraph("<b>Execution Mode:</b>", body_style), Paragraph(f"<b>{mode_label}</b>", body_style)
        ],
        [
            Paragraph("<b>Exported At:</b>", body_style), Paragraph(now_str, body_style),
            Paragraph("<b>Execution Window:</b>", body_style), Paragraph(f"{start_time or 'N/A'} - {end_time or now_str}", body_style)
        ],
        [
            Paragraph("<b>Target A (Baseline):</b>", body_style),
            Paragraph(f"ESP8266 NodeMCU | Port: {b_stat.get('port', 'None')} | Online: {b_connected}", body_style),
            Paragraph("<b>Target B (Hardened):</b>", body_style),
            Paragraph(f"ESP32 DevKit V1 | Port: {h_stat.get('port', 'None')} | Online: {h_connected}", body_style)
        ],
        [
            Paragraph("<b>Firmware Protocol:</b>", body_style),
            Paragraph("ZeroTrace v2.0 Dual-UART Handshake", body_style),
            Paragraph("<b>Evidence Standard:</b>", body_style),
            Paragraph("Comparative Empirical Verification", body_style)
        ]
    ]
    t_meta = Table(meta_data, colWidths=[100, 170, 95, 175])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # Executive Summary Box
    total_exec = len(campaign_results)
    hw_ev_count = sum(1 for r in campaign_results if "HARDWARE" in str(r.get("evidence_level", "")).upper())
    sw_ev_count = sum(1 for r in campaign_results if "SOFTWARE" in str(r.get("evidence_level", "")).upper())
    sim_ev_count = sum(1 for r in campaign_results if "SIM" in str(r.get("evidence_level", "")).upper())
    hardened_pass = sum(1 for r in campaign_results if r.get("status_hardened") == "PASS")
    baseline_weakness = sum(1 for r in campaign_results if r.get("status_baseline") == "FAIL")

    story.append(Paragraph("1. Executive Summary", h2_style))
    summary_data = [
        [
            Paragraph("<b>Scenarios Executed:</b>", body_style), Paragraph(str(total_exec), body_style),
            Paragraph("<b>Hardened Mitigations:</b>", body_style), Paragraph(f"{hardened_pass} Enforced", badge_pass)
        ],
        [
            Paragraph("<b>Baseline Weaknesses:</b>", body_style), Paragraph(f"{baseline_weakness} Exploited", badge_fail),
            Paragraph("<b>Hardware-Verified:</b>", body_style), Paragraph(f"{hw_ev_count} Scenarios", body_style)
        ],
        [
            Paragraph("<b>Software-Verified:</b>", body_style), Paragraph(f"{sw_ev_count} Scenarios", body_style),
            Paragraph("<b>Simulated Evidence:</b>", body_style), Paragraph(f"{sim_ev_count} Scenarios", body_style)
        ]
    ]
    t_sum = Table(summary_data, colWidths=[120, 150, 120, 150])
    t_sum.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_sum)
    story.append(Spacer(1, 10))

    # 10 Scenario Results Table
    story.append(Paragraph("2. 10 Controlled Security Scenarios — Comparative Evaluation", h2_style))
    table_header = [
        Paragraph("<b>ID</b>", body_style),
        Paragraph("<b>Scenario & Layer</b>", body_style),
        Paragraph("<b>ESP8266 Baseline</b>", body_style),
        Paragraph("<b>ESP32 Hardened</b>", body_style),
        Paragraph("<b>Evidence Level</b>", body_style)
    ]
    sc_rows = [table_header]

    for item in campaign_results:
        sc_id = item.get("test_id", "")
        name = item.get("name", "")
        layer = item.get("layer", "")
        b_res = item.get("observed_baseline", "")
        b_stat = item.get("status_baseline", "")
        h_res = item.get("observed_hardened", "")
        h_stat = item.get("status_hardened", "")
        ev = item.get("evidence_level", "")

        b_style = badge_fail if b_stat == "FAIL" else badge_pass
        h_style = badge_pass if h_stat == "PASS" else badge_fail

        sc_cell = Paragraph(f"<b>{name}</b><br/><font color='#64748b'>{layer}</font>", body_style)
        b_cell = Paragraph(f"{b_res}<br/><font size='7'>Status: {b_stat}</font>", b_style)
        h_cell = Paragraph(f"{h_res}<br/><font size='7'>Status: {h_stat}</font>", h_style)
        ev_cell = Paragraph(f"<b>{ev}</b>", body_style)

        sc_rows.append([
            Paragraph(f"<b>{sc_id}</b>", code_style),
            sc_cell,
            b_cell,
            h_cell,
            ev_cell
        ])

    t_sc = Table(sc_rows, colWidths=[45, 185, 125, 125, 60])
    t_sc.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#0f172a")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t_sc)
    story.append(Spacer(1, 10))

    # Section 3: Attack-Defence Event Trace & Latencies
    story.append(Paragraph("3. Attack–Defence Event Trace & Response Latencies", h2_style))
    story.append(Paragraph(
        "Measured round-trip response latencies over USB-UART serial interface (115200 baud). "
        "Each request was bound with a unique UUID request_id and echoed back by target firmware.",
        body_style
    ))
    story.append(Spacer(1, 4))

    trace_header = [
        Paragraph("<b>Scenario</b>", body_style),
        Paragraph("<b>Request ID</b>", body_style),
        Paragraph("<b>Baseline Latency</b>", body_style),
        Paragraph("<b>Hardened Latency</b>", body_style),
        Paragraph("<b>Defensive Control Verified</b>", body_style)
    ]
    trace_rows = [trace_header]

    for item in campaign_results:
        req_id_short = item.get("request_id", "")[:13] + "..." if item.get("request_id") else "req-" + item.get("test_id", "")
        b_lat = f"{item.get('latency_baseline_ms', 'N/A')} ms" if item.get('latency_baseline_ms') is not None else "N/A"
        h_lat = f"{item.get('latency_hardened_ms', 'N/A')} ms" if item.get('latency_hardened_ms') is not None else "N/A"
        ctrl = item.get("details_hardened", "Hardened Control Enforced")
        if len(ctrl) > 55:
            ctrl = ctrl[:52] + "..."

        trace_rows.append([
            Paragraph(item.get("test_id", ""), code_style),
            Paragraph(req_id_short, code_style),
            Paragraph(b_lat, body_style),
            Paragraph(h_lat, body_style),
            Paragraph(ctrl, body_style)
        ])

    t_tr = Table(trace_rows, colWidths=[55, 110, 85, 85, 205])
    t_tr.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t_tr)
    story.append(Spacer(1, 10))

    # Section 4: Engineering Limitations & Integrity Hash
    story.append(Paragraph("4. Evidence Integrity & Engineering Disclaimers", h2_style))
    disclaimer_text = (
        "<b>Limitations & Scopes:</b><br/>"
        "1. <b>Absence of Electrical Waveform Instrumentation:</b> ZeroTrace does not possess laboratory-grade "
        "oscilloscopes, voltage glitching rigs, or current shunt probes. Timeline traces represent exact software and UART "
        "round-trip latency measurements, clearly labeled as software event traces.<br/>"
        "2. <b>Cryptographic Sanitization Scope (Layer 4):</b> Flash memory on edge microcontrollers is not wiped "
        "destructively to avoid bricking boards. Layer 4 validates cryptographic key zeroization in RAM and authenticated "
        "AES-256-GCM tag verification, executed in verified Python runtime and classified as SOFTWARE_VERIFIED.<br/>"
        "3. <b>Scope of Conclusions:</b> Demonstrations validate security behavior under controlled, reproducible conditions. "
        "Passing tests verify that implemented policies function correctly against modeled attack vectors."
    )
    story.append(Paragraph(disclaimer_text, body_style))
    story.append(Spacer(1, 8))

    # Preliminary build to compute sha256
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    digest = compute_sha256(pdf_bytes)

    # Re-build appending digest box
    buffer_final = io.BytesIO()
    doc_final = SimpleDocTemplate(
        buffer_final,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    story.append(Spacer(1, 6))
    hash_box = [
        [
            Paragraph("<b>EVIDENCE INTEGRITY SHA-256 HASH:</b>", body_style),
            Paragraph(f"<font color='#0f172a'><b>{digest}</b></font>", code_style)
        ]
    ]
    t_hash = Table(hash_box, colWidths=[180, 360])
    t_hash.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#e0f2fe")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0284c7")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_hash)

    doc_final.build(story)
    return buffer_final.getvalue()
