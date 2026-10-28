# Layer 2 — Software-Based Fault Tolerance (SBFT)

## 1. Objective
Layer 2 detects anomalous hardware state corruption (e.g., simulated instruction skipping or bit-flips) using software-level redundancy and invariants, forcing the microcontroller into a fail-safe state.

Mapped to **NIST CSF 2.0**:
- **DE.CM-01**: Continuous Monitoring of Physical/Logical Environment
- **PR.IR-01**: Infrastructure Resilience & Safe-State Recovery

---

## 2. Invariant Architecture

Critical state is stored in dual-rail register pairs:
- **Primary Register ($R_1$)**
- **Complementary Inverted Register ($R_2 = \sim R_1$)**

**The Fundamental Invariant:**
$$R_1 \oplus R_2 == \text{0xFFFFFFFF}$$

If an unexpected transient fault flips any bit in either register, the XOR invariant breaks immediately, triggering a fault trap before corrupt state propagates to actuators or peripherals.

---

## 3. Scenarios Evaluated

| Scenario ID | Name | Expected Baseline | Expected Hardened | Defensive Action |
|---|---|---|---|---|
| `L2-SKIP-SIM` | Instruction Skip Anomaly | `INSTRUCTION_SKIPPED` | `ANOMALY_TRAPPED_RESET` | Dual-rail invariant catches single bit-flip; watchdog reset |
| `L2-UNROLL` | Loop Arithmetic Invariant | `UNCHECKED_CORRUPTION` | `INVARIANT_TRAP` | Accumulator invariant checks verified |
| `L2-AUTH` | Branch Flag Corruption | `UNAUTH_BYPASS` | `DOUBLE_CHECK_TRAP` | Hardened multi-step check prevents branch bypass |
| `L2-WATCHDOG` | Deadlock / Infinite Loop | `SYSTEM_HANG` | `WATCHDOG_RECOVERY` | Hardware watchdog timeout triggers reboot |
| `L2-REPEATED` | Glitch Burst | `CASCADE_FAILURE` | `CIRCUIT_BREAKER_TRIPPED` | Rate-limiter trips lockdown after 3 bursts |
