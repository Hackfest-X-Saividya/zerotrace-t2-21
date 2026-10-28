# ZeroTrace Evaluator Demonstration Script

Follow this 4-round demonstration sequence to present the 4-Layer Zero-Trust Framework to academic evaluators or stakeholders.

---

## Pre-Flight Check (30 seconds)
1. Start the ZeroTrace backend:
   ```bash
   cd ~/Desktop/ZeroTrace
   source venv/bin/activate
   python3 -m uvicorn backend.main:app --port 8000
   ```
2. Open Chrome/Safari to `http://127.0.0.1:8000/`.
3. Verify connection badges in the top header. (Works in Level 0 Simulation or Level 1-3 Hardware).

---

## Round 1: Layer 1 — Secure Boot & Anti-Rollback (Protect PR.PS)
1. **Goal:** Demonstrate that simple checksums allow tampering and downgrades, whereas HMAC and monotonic counters neutralize both.
2. **Action in Red Tab:**
   - Click **Layer 1 Filter** in the test selector.
   - Run **Scenario `L1-MODIFIED`** (Tampered Payload).
   - Run **Scenario `L1-ROLLBACK`** (Version 0 Downgrade).
3. **Evidence in Blue Tab:**
   - **Baseline (Target A):** Accepts the tampered binary (`ACCEPTED_WEAKNESS`) and downgrades to v0 without checking monotonic storage.
   - **Hardened (Target B):** MbedTLS HMAC-SHA256 catches signature mismatch (`REJECTED_CRYPTO_FAIL`); NVS monotonic policy blocks downgrade (`REJECTED_DOWNGRADE`).
   - Risk log emitted: `[RISK ASSESSED: CRITICAL] MITM Cryptographic Mismatch...`.

---

## Round 2: Layer 2 — Software-Based Fault Tolerance (Detect DE.CM)
1. **Goal:** Demonstrate that single-variable execution can be bypassed or corrupted by transient faults, whereas dual-rail complementary encoding traps anomalies.
2. **Action in Red Tab:**
   - Click **Layer 2 Filter**.
   - Run **Scenario `L2-SKIP-SIM`** (Simulated Fault Pulse).
   - Run **Scenario `L2-UNROLL`** (Loop Unroll Invariant).
3. **Evidence in Blue Tab:**
   - **Baseline (Target A):** State variable corrupted silently (0x5A5A -> 0x5A5B) with zero detection (`INSTRUCTION_SKIPPED`).
   - **Hardened (Target B):** Dual-rail invariant assertion (`hardened_state ^ hardened_state_inv == 0xFFFF`) triggers anomaly trap (`ANOMALY_TRAPPED_RESET`).

---

## Round 3: Layer 3 — Silicon Lockdown (Protect PR.AA)
1. **Goal:** Illustrate how boot-time debug policies protect against memory extraction.
2. **Action in Red Tab:**
   - Click **Layer 3 Filter**.
   - Run **Scenario `L3-POLICY-SIM`** (Debug-Lock Policy Verification).
3. **Evidence in Blue Tab:**
   - **Baseline (Target A):** Debug policy register is unconfigured; simulated JTAG port remains accessible (`UNLOCKED_DEBUG_LEAK`).
   - **Hardened (Target B):** Validates redundant policy registers at boot and enforces simulated debug-lock state (`SIMULATED_LOCK_ENFORCED`).

---

## Round 4: Layer 4 — Zero-Wear Cryptographic Key Sanitization (Respond RS.MI)
1. **Goal:** Demonstrate that merely deleting a pointer leaves secrets extractable, whereas active zeroization scrubs RAM before unlinking.
2. **Action in Red Tab:**
   - Click **Layer 4 Filter**.
   - Run **Scenario `L4-KEY-ZEROIZE`** (Key Memory Sanitization).
3. **Evidence in Blue Tab:**
   - **Baseline (Target A):** Only clears the pointer flag; 38 key bytes remain extractable in RAM (`POINTER_REMOVED_KEY_LEAKED`).
   - **Hardened (Target B):** Overwrites key buffer with zeros via volatile memory loops in under 500 µs (`ZEROIZED_AND_UNLINKED`).

---

## Concluding Screen: "What We Do NOT Claim"
Conclude the presentation by opening the **Limitations Modal** or displaying [`docs/limitations.md`](file:///Users/shashiprakashmaurya/Desktop/ZeroTrace/docs/limitations.md):
- We do **not** claim discovery of new zero-day vulnerabilities.
- We do **not** claim physical lab-grade electromagnetic or crowbar fault injection.
- Zeroizing RAM does **not** prove external unencrypted flash silicon remnants are gone.
- Results are transparently tagged with exact evidence levels: `simulation` vs `software-level` vs `hardware-assisted`.
- Framework mappings are **aligned with** NIST CSF 2.0 guidelines, not government certified.
