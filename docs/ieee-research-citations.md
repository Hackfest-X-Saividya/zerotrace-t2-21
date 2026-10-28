# ZeroTrace Research Citations & Literature Grounding

ZeroTrace references exclusively six published peer-reviewed works in embedded security, fault injection, and secure bootloader design.

---

## 1. Primary Academic Sources

### 1. Fanjas et al. (2023) — SoC Secure-Boot Fault Injection Timing
> **Citation:** C. Fanjas, D. Aboulkassimi, S. Pontié, and J. Clédière, *"Exploration of System-on-Chip Secure-Boot Vulnerability to Fault-Injection by Side-Channel Analysis,"* in **2023 IEEE International Symposium on Defect and Fault Tolerance in VLSI and Nanotechnology Systems (DFT)**, IEEE, 2023, pp. 1–6. DOI: [10.1109/DFT59622.2023.10313346](https://doi.org/10.1109/DFT59622.2023.10313346).
- **Exact Documented Data:**
  - Identifies 5 critical comparison vulnerabilities in multi-stage bootloader chains (p. 3, Fig. 2B: V1 fuse check, V2 root certificate hash compare, V3 certificate 0 check).
  - Measures experimental timing divergence offsets using side-channel analysis: V1 at 45.12 µs (p. 4), V2 at 4.95 µs (p. 5), V3 at 6.733 ms (p. 4).
- **ZeroTrace Application:** Informs the structure of Layer 1 (Secure Boot & OTA), establishing that cryptographic signature checking and health verification must occur before staging code into executable memory.

---

### 2. Luo et al. (2022) — TrustZone-M & Firmware Downgrade Attacks
> **Citation:** L. Luo, Y. Zhang, C. White, B. Keating, B. Pearson, X. Shao, Z. Ling, H. Yu, C. Zou, and X. Fu, *"On Security of TrustZone-M-Based IoT Systems,"* in **IEEE Internet of Things Journal**, vol. 9, no. 12, pp. 9683–9699, June 15, 2022. DOI: [10.1109/JIOT.2022.3144405](https://doi.org/10.1109/JIOT.2022.3144405).
- **Exact Documented Data:**
  - Evaluates firmware rollback / downgrade exploits against microcontroller non-volatile storage (Section III-E, p. 9686; Section VII-B, p. 9695).
  - Outlines the five security dimensions for constrained IoT devices: hardware, boot-time software, runtime software, network, and OTA update (Table I, p. 9685).
- **ZeroTrace Application:** Informs the Layer 1 Monotonic Counter Anti-Rollback policy, verifying version numbers against non-volatile memory to prevent replay of legacy signed binaries.

---

### 3. Fanjas et al. (2024) — Fault Injection Models & Instruction Skips
> **Citation:** C. Fanjas, D. Aboulkassimi, S. Pontié, and J. Clédière, *"PoP DRAM: A new EMFI approach based on EM-induced glitches on SoC,"* in **2024 Workshop on Fault Detection and Tolerance in Cryptography (FDTC)**, IEEE, 2024, pp. 10–21. DOI: [10.1109/FDTC64268.2024.00010](https://doi.org/10.1109/FDTC64268.2024.00010).
- **Exact Documented Data:**
  - Classifies empirical fault injection outcomes into nine formal fault models (p. 13-14, Table I): F.1 (arithmetic subtraction instruction skip), F.3 (comparison instruction skip), and F.6 (counter decrement skip).
- **ZeroTrace Application:** Informs the Layer 2 Software-Based Fault Tolerance (SBFT) scenarios (`L2-SKIP-SIM`, `L2-UNROLL`, and `L2-AUTH`), where instruction skip and branch corruption behaviors are simulated and caught via invariant traps.

---

### 4. Wiersma and Pareja (2017) — Safety != Security in Automotive MCUs
> **Citation:** N. Wiersma and R. Pareja, *"Safety != Security: On the resilience of ASIL-D certified microcontrollers against fault injection attacks,"* in **2017 Workshop on Fault Diagnosis and Tolerance in Cryptography (FDTC)**, IEEE, 2017, pp. 9–16. DOI: [10.1109/FDTC.2017.15](https://doi.org/10.1109/FDTC.2017.15).
- **Exact Documented Data:**
  - Demonstrates that safety mechanisms (lockstep cores, memory ECC) fail to prevent fault injection, with JTAG debug unlock rates reaching 1.3% on ASILD1 and 80% on QM1 targets (p. 14, Table III).
- **ZeroTrace Application:** Informs Layer 3 (Silicon Lockdown), illustrating that debug access must be enforced via multi-layer policy checks rather than assuming silicon safety features alone suffice.

---

### 5. Lethaby (2018) — Secure OAD Concepts & Rollback Protection
> **Citation:** N. Lethaby, *"Secure OAD (Over-the-Air Download) for IoT Microcontrollers,"* Texas Instruments Technical White Paper, SPRAAA0, 2018.
- **Exact Documented Data:**
  - Details the necessity of dual-image staging, boot validation, cryptographic signature checking, and hardware anti-rollback counters to protect wireless and serial firmware updates.
- **ZeroTrace Application:** Informs our staging buffer architecture and monotonic counter implementation for OTA serial update verification.

---

### 6. El Jaouhari and Bouvet (2022) — Secure Firmware Update Architectures
> **Citation:** S. El Jaouhari and E. Bouvet, *"Secure Firmware Update Architecture for Constrained IoT Devices,"* in **2022 36th International Conference on Information Networking (ICOIN)**, IEEE, 2022, pp. 88–93. DOI: [10.1109/ICOIN53456.2022.9723223](https://doi.org/10.1109/ICOIN53456.2022.9723223).
- **Exact Documented Data:**
  - Evaluates memory overhead, bootloader verification latency, and fail-safe recovery schemes for resource-constrained ARM Cortex-M and ESP microcontrollers.
- **ZeroTrace Application:** Informs our Golden Image recovery pattern and probationary boot self-test mechanics.

---

## 2. Author Assumptions & Clarifications

> [!IMPORTANT]
> **Explicit Engineering Assumption:**
> The **8.5 µs pulse duration** used in our testbed is **our own design assumption** for a safe, software-simulated GPIO trigger between microcontrollers. It is **not** a physical threshold claim from the cited research literature.
