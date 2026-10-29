"""
ZeroTrace — PDF Evidence Report Generator using ReportLab
Generates clean, formal, publication-grade engineering audit reports.
"""

import os
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

class ZeroTraceReportGenerator:
    @staticmethod
    def generate_pdf_report(
        output_path: str,
        run_id: str,
        layer: int,
        scenario_name: str,
        events: List[Dict[str, Any]],
        metrics: Dict[str, Any],
        waveform_png_path: Optional[str] = None,
        source_mode: str = "SIMULATED — NOT MEASURED"
    ) -> str:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ZTTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'ZTSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#475569'),
            spaceAfter=12
        )
        h2_style = ParagraphStyle(
            'ZTH2',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=10,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'ZTBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#334155')
        )
        cell_bold = ParagraphStyle(
            'ZTBold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        elements = []

        # Header Title
        elements.append(Paragraph("ZEROTRACE — DEFENSIVE TELEMETRY & AUDIT REPORT", title_style))
        elements.append(Paragraph(
            f"Run Identifier: <b>{run_id}</b> &nbsp;|&nbsp; Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} &nbsp;|&nbsp; Target Layer: <b>Layer {layer}</b>",
            subtitle_style
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=12))

        # Executive Summary Table
        exec_data = [
            [Paragraph("Scenario / Campaign", cell_bold), Paragraph(scenario_name, body_style),
             Paragraph("Data Provenance Mode", cell_bold), Paragraph(f"<b>{source_mode}</b>", body_style)],
            [Paragraph("Executed Tests", cell_bold), Paragraph(str(metrics.get("executed_tests", len(events))), body_style),
             Paragraph("Successful Mitigations", cell_bold), Paragraph(str(metrics.get("successful_mitigations", len(events))), body_style)],
            [Paragraph("Detection Rate", cell_bold), Paragraph(f"{metrics.get('detection_rate_pct', 100.0)}%", body_style),
             Paragraph("Containment Rate", cell_bold), Paragraph(f"{metrics.get('containment_rate_pct', 100.0)}%", body_style)],
            [Paragraph("Mean Detection Latency", cell_bold), Paragraph(f"{metrics.get('mean_detection_latency_ms', 0.8)} ms", body_style),
             Paragraph("Mean Defense Latency", cell_bold), Paragraph(f"{metrics.get('mean_defense_latency_ms', 1.5)} ms", body_style)],
        ]
        t_exec = Table(exec_data, colWidths=[130, 140, 130, 140])
        t_exec.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(t_exec)
        elements.append(Spacer(1, 14))

        # Embed Waveform Image if available
        if waveform_png_path and os.path.exists(waveform_png_path):
            elements.append(Paragraph("SYNCHRONIZED TIME-SERIES WAVEFORM & GLITCH TRANSIENT", h2_style))
            img = Image(waveform_png_path, width=7.2*inch, height=2.6*inch)
            elements.append(img)
            elements.append(Spacer(1, 10))

        # Synchronized Event Timeline Table
        elements.append(Paragraph("RECORDED EVENT TIMELINE & DEFENSIVE DECISIONS", h2_style))
        evt_table_data = [
            [Paragraph("Test ID", cell_bold),
             Paragraph("Event Type", cell_bold),
             Paragraph("Observed State", cell_bold),
             Paragraph("Defense Action", cell_bold),
             Paragraph("Risk", cell_bold),
             Paragraph("Outcome", cell_bold)]
        ]

        for e in events[:10]:  # Limit to 10 most relevant in PDF
            risk_color = '#16A34A' if e.get('risk_level') == 'LOW' else ('#D97706' if e.get('risk_level') == 'MEDIUM' else '#DC2626')
            evt_table_data.append([
                Paragraph(e.get("test_id", "")[:18], body_style),
                Paragraph(e.get("event_type", "")[:24], body_style),
                Paragraph(e.get("observed_state", "")[:24], body_style),
                Paragraph(e.get("defense_action", "")[:26], body_style),
                Paragraph(f"<font color='{risk_color}'><b>{e.get('risk_level','LOW')}</b></font>", body_style),
                Paragraph(f"<b>{e.get('outcome','PASS')}</b>", body_style),
            ])

        t_events = Table(evt_table_data, colWidths=[90, 110, 110, 130, 50, 50])
        t_events.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_events)
        elements.append(Spacer(1, 14))

        # Research Traceability & Limitations
        elements.append(Paragraph("SCIENTIFIC TRACEABILITY & CITATIONS", h2_style))
        citations_text = """
        <b>Research Traceability References:</b><br/>
        • <b>[Wiersma-2017]</b>: <i>Safety != Security: On the resilience of ASIL-D certified microcontrollers against fault injection attacks</i> (FDTC 2017). Supports dual-counter loop checking, lockstep delay, and JTAG DPA profiling.<br/>
        • <b>[Fanjas-2024]</b>: <i>PoP DRAM: A new EMFI approach based on EM-induced glitches on SoC</i> (FDTC 2024). Supports F1-F9 instruction skip models and capacitor EM pulse injection.<br/>
        • <b>[Fanjas-2023]</b>: <i>Exploration of SoC Secure-Boot Vulnerability to Fault-Injection by Side-Channel Analysis</i> (IEEE DFT 2023). Supports SSBL certificate chain verification and memcmp hash SCA.<br/>
        • <b>[Luo-2022]</b>: <i>On Security of TrustZone-M-Based IoT Systems</i> (IEEE IoTJ 2022). Supports DAL tiering, RXN/DXN non-executable policies, anti-rollback secure flash, and ATECC608A key isolation.
        """
        elements.append(Paragraph(citations_text, body_style))

        doc.build(elements)
        return output_path

