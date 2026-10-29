"""
ZeroTrace — End-to-End Test Suite for All 40 Problems & Automated Evidence Generation
"""

import os
from backend.catalog.problem_catalog import PROBLEM_CATALOG
from backend.main import execute_single_problem_test
from backend.config import STATUS_PASS, EXPORTS_DIR
from backend.telemetry.waveform_generator import WaveformGenerator
from backend.analytics.metrics_engine import MetricsEngine
from backend.evidence.exporter import EvidenceExporter

def test_all_40_problems_execution_and_pass():
    assert len(PROBLEM_CATALOG) == 40, "Must have exactly 40 defined security problems"
    
    wave_gen = WaveformGenerator(sample_rate_hz=5000)
    passed_count = 0
    run_id = "E2E_VERIFICATION_CAMPAIGN"

    for problem_id, p_def in PROBLEM_CATALOG.items():
        events = execute_single_problem_test(problem_id, run_id)
        assert len(events) >= 1, f"Problem {problem_id} produced no event records"
        # Verify that all events pass
        for e in events:
            assert e.outcome == STATUS_PASS, f"Problem {problem_id} event {e.event_type} failed"
        passed_count += 1

    assert passed_count == 40, "All 40 problems must pass their verification tests"

def test_evidence_export_all_four_formats():
    run_id = "EXPORT_TEST_001"
    p = PROBLEM_CATALOG["SEC-L2-02"]
    events = execute_single_problem_test("SEC-L2-02", run_id)
    
    wave_gen = WaveformGenerator(sample_rate_hz=5000)
    waveform = wave_gen.generate_scenario_waveform(run_id, p.test_id, "VOLTAGE_GLITCH", duration_ms=5.0, events=events)
    metrics = MetricsEngine.calculate_layer_metrics(2, events).model_dump()

    files = EvidenceExporter.export_evidence_package(
        run_id=run_id, layer=2, scenario_name=p.title,
        waveform=waveform, events=events, metrics=metrics
    )

    # Verify all 4 files exist and are non-empty
    for k in ["pdf", "png", "csv", "json"]:
        assert k in files
        f_path = files[k]
        assert os.path.exists(f_path), f"File {f_path} was not created"
        assert os.path.getsize(f_path) > 0, f"File {f_path} is empty"

