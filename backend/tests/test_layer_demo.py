"""
Tests for Security Layer Demo & Waveform Comparison Engine:
- Synthetic array math validation (RMSE, Pearson r, match percentage)
- Clean match scenario
- Noisy match scenario
- Non-match scenario
- Inconclusive scenario (attack indistinguishable from baseline)
- Simulated layer demo generation
"""

import math
import pytest
from backend.telemetry.layer_demo import (
    compute_rmse,
    compute_pearson_correlation,
    compute_match_percentage,
    evaluate_layer_demo_metrics,
    generate_simulated_layer_demo
)


def test_rmse_and_correlation_math():
    """Validates baseline math on known deterministic arrays."""
    a = [1.0, 2.0, 3.0, 4.0, 5.0]
    b = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert compute_rmse(a, b) == 0.0
    assert compute_pearson_correlation(a, b) == 1.0

    # Inverted signal has correlation -1.0
    c = [5.0, 4.0, 3.0, 2.0, 1.0]
    assert pytest.approx(compute_pearson_correlation(a, c), 0.001) == -1.0

    # Constant signal with offset
    d = [2.0, 3.0, 4.0, 5.0, 6.0]
    assert pytest.approx(compute_rmse(a, d), 0.001) == 1.0
    assert pytest.approx(compute_pearson_correlation(a, d), 0.001) == 1.0


def test_clean_match_scenario():
    """Tests a clean defense where defended matches baseline within noise floor."""
    n = 200
    base_a = [2.5 + 0.5 * math.sin(i * 0.1) for i in range(n)]
    base_b = [base_a[i] + (0.01 if i % 2 == 0 else -0.01) for i in range(n)]

    # Attack: noticeable voltage offset and distortion
    attack = [base_a[i] + (1.2 if i % 3 == 0 else -0.8) for i in range(n)]

    # Defended: clean recovery identical to baseline with tiny variation
    defended = [base_a[i] + (0.012 if i % 3 == 0 else -0.012) for i in range(n)]

    res = evaluate_layer_demo_metrics(base_a, base_b, attack, defended, layer=2, is_measured=True)
    assert res["verdict"] == "PASS"
    assert res["match_pct"] >= 90.0
    assert res["provenance"] == "PHYSICAL_MEASUREMENT"
    assert res["metrics"]["defended_rmse"] <= 3.0 * res["metrics"]["noise_floor_rmse"]


def test_noisy_match_scenario():
    """Tests that a noisy match within 3x noise floor passes."""
    n = 200
    base_a = [2.5 + 0.4 * math.sin(i * 0.1) for i in range(n)]
    base_b = [base_a[i] + (0.015 if i % 2 == 0 else -0.015) for i in range(n)]

    # Attack: large glitch spikes
    attack = [base_a[i] + (1.8 if i % 5 == 0 else -0.9) for i in range(n)]

    # Defended: noisy but bounded within 2.5x noise floor
    defended = [base_a[i] + (0.03 if i % 2 == 0 else -0.03) for i in range(n)]

    res = evaluate_layer_demo_metrics(base_a, base_b, attack, defended, layer=1, is_measured=True)
    assert res["verdict"] == "PASS"
    assert res["provenance"] == "MEASURED (controlled testbed, attack signature injected by Uno firmware)"
    assert res["match_pct"] >= 75.0


def test_non_match_scenario():
    """Tests that a corrupted or unrecovered defended waveform fails."""
    n = 200
    base_a = [2.5 + 0.5 * math.sin(i * 0.1) for i in range(n)]
    base_b = [base_a[i] + (0.01 if i % 2 == 0 else -0.01) for i in range(n)]

    attack = [base_a[i] - 1.5 for i in range(n)]
    # Defended still has massive offset error
    defended = [base_a[i] - 1.2 for i in range(n)]

    res = evaluate_layer_demo_metrics(base_a, base_b, attack, defended, layer=3, is_measured=True)
    assert res["verdict"] == "FAIL"
    assert res["match_pct"] < 60.0


def test_inconclusive_scenario():
    """Tests that if the attack is indistinguishable from baseline, run is INCONCLUSIVE."""
    n = 200
    base_a = [2.5 + 0.5 * math.sin(i * 0.1) for i in range(n)]
    base_b = [base_a[i] + (0.02 if i % 2 == 0 else -0.02) for i in range(n)]

    # Attack is virtually identical to baseline noise floor
    attack = [base_a[i] + (0.018 if i % 2 == 0 else -0.018) for i in range(n)]
    defended = [base_a[i] for i in range(n)]

    res = evaluate_layer_demo_metrics(base_a, base_b, attack, defended, layer=4, is_measured=True)
    assert res["verdict"] == "INCONCLUSIVE"
    assert "not statistically distinguishable" in res["verdict_reason"]


def test_simulated_layer_demos_all_layers():
    """Tests synthetic simulation generation for all 4 security layers."""
    for layer in (1, 2, 3, 4):
        demo = generate_simulated_layer_demo(layer)
        assert demo["layer"] == layer
        assert demo["verdict"] == "PASS"
        assert demo["provenance"] == "SIMULATED — NOT MEASURED"
        assert len(demo["time_ms"]) == 500
        assert len(demo["baseline_a"]) == 500
        assert len(demo["attack"]) == 500
        assert len(demo["defended"]) == 500
        assert demo["match_pct"] >= 80.0


def test_api_layer_demo_endpoints():
    """Tests POST & GET /api/waveform/layer-demo via TestClient."""
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)

    # 1. Post Layer Demo for Layer 2
    res = client.post("/api/waveform/layer-demo?layer=2")
    assert res.status_code == 200
    data = res.json()
    assert data["layer"] == 2
    assert "baseline_a" in data
    assert "attack" in data
    assert "defended" in data
    assert "match_pct" in data
    assert "verdict" in data
    assert "metrics" in data

    # 2. Get Layer Demo for Layer 2
    get_res = client.get("/api/waveform/layer-demo?layer=2")
    assert get_res.status_code == 200
    assert get_res.json()["layer"] == 2

    # 3. Invalid Layer (e.g. 5) returns 400
    err_res = client.post("/api/waveform/layer-demo?layer=5")
    assert err_res.status_code == 400

    # 4. Run all layers endpoint
    all_res = client.post("/api/waveform/layer-demo/all")
    assert all_res.status_code == 200
    all_data = all_res.json()
    assert len(all_data["results"]) == 4


def test_problems_api_endpoint():
    """Validates GET /api/problems returns the 40-problem catalog with honest classifications."""
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)
    res = client.get("/api/problems")
    assert res.status_code == 200
    problems = res.json()
    assert len(problems) == 40

    # Verify schema fields on each problem
    for p in problems:
        assert "problem_id" in p
        assert "layer" in p
        assert "title" in p
        assert "attack" in p
        assert "observable" in p
        assert "defense" in p
        assert "metric" in p
        assert "threshold_source" in p
        assert "provenance" in p
        assert p["provenance"] in ("MEASURED", "PARTIAL", "MODELED")
        assert p["implemented"] is True

    # Test filtering by layer
    res_l2 = client.get("/api/problems?layer=2")
    assert res_l2.status_code == 200
    l2_probs = res_l2.json()
    assert len(l2_probs) == 10
    assert all(p["layer"] == 2 for p in l2_probs)


def test_layer_demo_metadata_and_telemetry():
    """Validates all 4 layers include plain-language educational cards and dynamic axis metadata."""
    from backend.telemetry.layer_demo import generate_simulated_layer_demo

    for layer in (1, 2, 3, 4):
        demo = generate_simulated_layer_demo(layer)
        assert "scenario_title" in demo and len(demo["scenario_title"]) > 5
        assert "what_attacker_does" in demo and len(demo["what_attacker_does"]) > 10
        assert "what_we_measure" in demo and len(demo["what_we_measure"]) > 10
        assert "how_defense_works" in demo and len(demo["how_defense_works"]) > 10
        assert "what_pass_means" in demo and len(demo["what_pass_means"]) > 10
        assert "x_axis_label" in demo
        assert "y_axis_label" in demo
        assert "y_unit" in demo
        assert "extra_telemetry" in demo
        assert isinstance(demo["extra_telemetry"], dict)

