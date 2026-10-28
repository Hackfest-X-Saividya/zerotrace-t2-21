# ZeroTrace Automated Testing Guide

## 1. Running Backend Unit & Integration Tests

The test suite validates catalog integrity, deterministic simulation outcomes, regex parsing, all 4 layers, credential generation, and cryptographic sanitization.

Run the test suite using pytest from the repository root:

```bash
cd /Users/shashiprakashmaurya/Desktop/ZeroTrace
PYTHONPATH=. ./venv/bin/pytest tests/ -v
```

Expected output:
```text
tests/test_backend.py::test_catalog_loads_and_has_required_scenarios PASSED
tests/test_backend.py::test_simulation_engine_baseline_vs_hardened PASSED
tests/test_backend.py::test_regex_risk_log_parser PASSED
tests/test_backend.py::test_all_22_csf_categories_defined PASSED
tests/test_backend.py::test_l3_policy_sim_esp8266_absent PASSED
tests/test_backend.py::test_device_profile_identification PASSED
tests/test_four_layers.py::test_credential_generation_and_verification PASSED
tests/test_four_layers.py::test_layer1_ota_scenarios PASSED
tests/test_four_layers.py::test_layer2_fault_tolerance_scenarios PASSED
tests/test_four_layers.py::test_layer3_silicon_lockdown PASSED
tests/test_four_layers.py::test_layer4_cryptographic_sanitization_lifecycle PASSED
tests/test_four_layers.py::test_event_service_redacts_forbidden_keys PASSED

======================== 12 passed in 0.34s ========================
```

---

## 2. CLI End-to-End Suite Execution

You can run the full automated evaluation suite against the live backend via CLI:

```bash
cd /Users/shashiprakashmaurya/Desktop/ZeroTrace
./venv/bin/python3 scripts/run_suite_cli.py
```

This sends all 9 scenarios sequentially to the backend and renders a markdown table comparing Target A (Baseline) and Target B (Hardened) observed results.

---

## 3. Frontend Production Build Verification

Verify that the React frontend compiles into production static bundles with zero errors:

```bash
cd /Users/shashiprakashmaurya/Desktop/ZeroTrace/frontend
npm run build
```
