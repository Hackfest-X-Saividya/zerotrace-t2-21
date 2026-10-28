#!/usr/bin/env python3
import urllib.request
import json

scenarios = [
    "L1-APPROVED", "L1-MODIFIED", "L1-ROLLBACK", "L1-BOOTFAIL-REVERT",
    "L4-KEY-ZEROIZE", "L2-SKIP-SIM", "L2-UNROLL", "L2-AUTH", "L3-POLICY-SIM"
]

results = []
for sc_id in scenarios:
    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/execute-test",
        data=json.dumps({"test_id": sc_id, "mode": "simulate"}).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        results.append(json.loads(resp.read().decode("utf-8")))

print("| Scenario ID | Name | Expected Baseline | Observed Baseline | Expected Hardened | Observed Hardened | Evidence Level | Result |")
print("|---|---|---|---|---|---|---|---|")
for r in results:
    tid = r["test_id"]
    name = r["name"]
    eb = r["expected_baseline"]
    ob = r["observed_baseline"]
    eh = r["expected_hardened"]
    oh = r["observed_hardened"]
    ev = r["evidence_level"]
    sh = r["status_hardened"]
    print(f"| **{tid}** | {name} | `{eb}` | `{ob}` | `{eh}` | `{oh}` | `{ev}` | **{sh}** |")
