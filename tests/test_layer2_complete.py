import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.layers.layer2.service import layer2_service, LAYER2_CSV_COLUMNS, SCENARIO_SPECS

client = TestClient(app)

L2_ALL_SCENARIOS = [
    "NORMAL",
    "INSTRUCTION_SKIP_SIMULATED",
    "CHECK_STATE_CORRUPTED",
    "COMMUNICATION_ERROR",
    "WATCHDOG_RESET",
    "RECOVERY_VERIFICATION",
    "MALFORMED_MESSAGE",
    "REPLAY_REQUEST",
    "STALE_OUT_OF_ORDER",
    "TIMEOUT_DROPPED",
    "FAIL_CLOSED_VERIFICATION",
]

def test_layer2_all_11_scenarios_direct():
    """Verify each of the 11 scenarios executes directly through Layer2Service."""
    import asyncio
    async def _test_all():
        for sc in L2_ALL_SCENARIOS:
            result = await layer2_service.execute_fault_scenario(sc, target_device="hardened", execution_mode="demo")
            assert "run_id" in result
            assert result["scenario"] == sc
            assert result["hardened"]["status"] == "PASS"
            assert len(result["events"]) == 4
            assert len(result["waveform_samples"]) >= 5
            assert "dual_rail_verified" in result
            # Verify fail-closed data safety: no raw secrets leaked
            assert "secret_key" not in result
            assert "private_token" not in result
            assert "root_ca_private" not in result
    asyncio.run(_test_all())

def test_layer2_dual_rail_invariant():
    """Verify dual rail invariant logic and anomaly detection."""
    # Test valid state
    layer2_service.state_r1 = 0xAA55AA55
    layer2_service.state_r2 = 0x55AA55AA
    assert layer2_service.verify_dual_rail_invariant() is True

    # Test corrupted state
    layer2_service.state_r2 = 0x55AA55A0
    assert layer2_service.verify_dual_rail_invariant() is False

def test_layer2_fail_closed_protected_data_safety():
    """Verify that under any simulated fault, protected cryptographic data is never released."""
    import asyncio
    async def _test_fail_closed():
        res = await layer2_service.execute_fault_scenario("FAIL_CLOSED_VERIFICATION")
        assert res["hardened"]["observed"] == "FAIL_CLOSED_ZEROIZED"
        assert res["system_state"] == "SAFE_STATE_TRAPPED"
        # Verify protected payload is safeguarded
        for evt in res["events"]:
            assert "super_secret_payload" not in str(evt)
    asyncio.run(_test_fail_closed())

def test_layer2_csv_export_19_columns():
    """Verify Layer 2 CSV export has all 19 standard columns."""
    csv_str = layer2_service.generate_csv_export()
    lines = csv_str.strip().split("\r\n") if "\r\n" in csv_str else csv_str.strip().split("\n")
    headers = [h.strip() for h in lines[0].split(",")]
    assert len(headers) == 19
    for col in LAYER2_CSV_COLUMNS:
        assert col in headers

def test_layer2_json_export_structure():
    """Verify Layer 2 JSON export includes provenance, metadata, and digest."""
    data = layer2_service.generate_json_export()
    assert "schema_version" in data
    assert "export_timestamp_utc" in data
    assert "sha256_digest" in data
    assert "run_metadata" in data
    assert "provenance" in data

def test_layer2_waveform_png_export():
    """Verify PNG waveform renders valid PNG bytes with Pillow."""
    png_bytes = layer2_service.generate_waveform_png()
    assert isinstance(png_bytes, bytes)
    assert len(png_bytes) > 500
    assert png_bytes.startswith(b"\x89PNG\r\n\x1a\n")

def test_layer2_pdf_report_export():
    """Verify PDF generation produces valid PDF bytes."""
    pdf_bytes = layer2_service.generate_pdf_report()
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")

def test_layer2_fastapi_endpoints():
    """Verify Layer 2 HTTP endpoints on FastAPI."""
    # Run scenario via POST /api/layer2/run
    resp = client.post("/api/layer2/run", json={"scenario": "L2-01", "target_device": "hardened"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario"] == "NORMAL"
    assert data["hardened"]["status"] == "PASS"

    # Status via GET /api/layer2/status
    s_resp = client.get("/api/layer2/status")
    assert s_resp.status_code == 200
    status_data = s_resp.json()
    assert "system_state" in status_data
    assert "dual_rail_verified" in status_data
    assert "supported_scenarios" in status_data
    assert len(status_data["supported_scenarios"]) == 11

    # History via GET /api/layer2/history
    h_resp = client.get("/api/layer2/history")
    assert h_resp.status_code == 200
    assert "history" in h_resp.json()

    # Exports via GET /api/layer2/export
    for fmt in ["csv", "json", "pdf", "png"]:
        e_resp = client.get(f"/api/layer2/export?format={fmt}")
        assert e_resp.status_code == 200
        assert len(e_resp.content) > 50
