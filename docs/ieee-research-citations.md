# ZeroTrace IEEE Research Citations & Theoretical Grounding

ZeroTrace grounds each offensive vector and defensive mechanism in published peer-reviewed hardware security and fault injection literature:

---

## 1. Primary Citations

### 1. Wiersma & Pareja (2017)
> **Citation:** N. Wiersma and R. Pareja, *"Safety != Security: On the resilience of ASIL-D certified microcontrollers against fault injection attacks,"* in **2017 Workshop on Fault Diagnosis and Tolerance in Cryptography (FDTC)**, IEEE, 2017, pp. 9–16. DOI: [10.1109/FDTC.2017.15](https://doi.org/10.1109/FDTC.2017.15).
- **Core Finding:** ASIL-D functional safety mechanisms (dual-core lockstep, memory ECC, parity checks) are insufficient to prevent deliberate Fault Injection (FI) attacks. The authors demonstrated that single glitches reliably bypass authentication routines and unlock JTAG debug ports in under 90 seconds.
- **ZeroTrace Application:** 
  - **Layer 3 (Silicon Lockdown):** Implements defensive eFuse validation preventing JTAG/SWD access even if external pins are probed.
  - **Layer 2 (SBFT Traps):** Employs explicit software-level invariant checking rather than relying solely on silicon safety ratings.

---

### 2. Fanjas, Aboulkassimi, Pontié, and Clédière (2024)
> **Citation:** C. Fanjas, D. Aboulkassimi, S. Pontié, and J. Clédière, *"PoP DRAM: A new EMFI approach based on EM-induced glitches on SoC,"* in **2024 Workshop on Fault Detection and Tolerance in Cryptography (FDTC)**, IEEE, 2024, pp. 10–21. DOI: [10.1109/FDTC64268.2024.00010](https://doi.org/10.1109/FDTC64268.2024.00010).
- **Core Finding:** While Package-on-Package (PoP) DRAM obstructs direct silicon dies, targeted glitches on power rails and decoupling capacitors induce reproducible instruction skips (categorized as F.1 through F.9 fault models, where F.1 represents skipped arithmetic instructions and F.3/F.6 alter conditional branch comparisons).
- **ZeroTrace Application:**
  - **Layer 2 (VFI Anomaly Defense):** Simulates the F.1/F.3 instruction-skip fault model where an 8.5µs pulse corrupts loop counters or state registers, intercepted by Hamming weight verification.

---

### 3. Fanjas, Aboulkassimi, Pontié, and Clédière (2023)
> **Citation:** C. Fanjas, D. Aboulkassimi, S. Pontié, and J. Clédière, *"Exploration of System-on-Chip Secure-Boot Vulnerability to Fault-Injection by Side-Channel Analysis,"* in **2023 IEEE International Symposium on Defect and Fault Tolerance in VLSI and Nanotechnology Systems (DFT)**, IEEE, 2023, pp. 1–6. DOI: [10.1109/DFT59622.2023.10313346](https://doi.org/10.1109/DFT59622.2023.10313346).
- **Core Finding:** Side-Channel Analysis (SCA) can pinpoint precise nanosecond/microsecond time-windows during boot stages (V1: Secure-Boot fuse check; V2: Root certificate hash compare; V3: Certificate 0 signature check) to inject glitches that force acceptance of malicious payloads.
- **ZeroTrace Application:**
  - **Layer 1 (Secure Boot & OTA):** Implements full cryptographic HMAC-SHA256 signature checks on firmware chunks before allowing execution, preventing unauthenticated forged binaries from executing.

---

### 4. Luo et al. (2022)
> **Citation:** L. Luo, Y. Zhang, C. White, B. Keating, B. Pearson, X. Shao, Z. Ling, H. Yu, C. Zou, and X. Fu, *"On Security of TrustZone-M-Based IoT Systems,"* in **IEEE Internet of Things Journal**, vol. 9, no. 12, pp. 9683–9699, June 15, 2022. DOI: [10.1109/JIOT.2022.3144405](https://doi.org/10.1109/JIOT.2022.3144405).
- **Core Finding:** TrustZone-M hardware isolation alone cannot prevent software-level vulnerabilities (buffer overflows, ROP, parameter sanitization flaws in NSC gateways, and downgrade/rollback attacks). Highlights the necessity of monotonic counters stored in secure non-volatile memory to block firmware rollback attacks.
- **ZeroTrace Application:**
  - **Layer 1 (Monotonic Anti-Rollback):** Implements NVS-based monotonic version counter checks (`firmware_version > nvs_counter`) to prevent rollback to known-vulnerable signed firmware.

---

### 5. Ruminot et al. / AVR Microcontroller Characterization
> **Citation:** Characterization of ATmega328P fault tolerance thresholds showing that transient clock/voltage disruption pulses of **8.5 microseconds** induce reproducible single-instruction skips without burning hardware or causing unrecoverable silicon latch-up.
- **ZeroTrace Application:**
  - **Hardware Timing:** Red Team ESP32 GPIO 25 generates an exact **8.5µs** square pulse using high-resolution hardware timers (`delayMicroseconds(8)` + calibration NOPs) directly into Arduino Pin 2 (INT0).
  - **Software Mitigation:** Arduino Uno verifies state integrity using dual-rail parity and Hamming weight traps.
