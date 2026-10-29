"""
ZeroTrace — 40 Security Problem Catalog
Contains 10 distinct security problems per layer (total 40)
"""

from typing import Dict, List
from backend.schema import SecurityProblemDef

PROBLEM_CATALOG: Dict[str, SecurityProblemDef] = {
    # -------------------------------------------------------------
    # LAYER 1: Secure Boot, OTA, and Firmware Integrity (10 Problems)
    # -------------------------------------------------------------
    "SEC-L1-01": SecurityProblemDef(
        problem_id="SEC-L1-01",
        layer=1,
        title="Firmware Package Authenticity & Untrusted Origin Rejection",
        security_objective="Ensure only authorized firmware images signed by a trusted certificate authority can be staged or installed.",
        threat_failure_mode="Attacker uploads forged firmware signed by an untrusted or arbitrary self-signed key, attempting remote code execution.",
        countermeasure="Root-of-Trust verification chain validating issuer signatures against on-device trust anchors stored in protected memory.",
        implementation_module="backend/layers/layer1_secure_boot.py::verify_firmware_package",
        test_id="test_l1_01_untrusted_origin",
        research_citations=["Fanjas et al. (DFT 2023) Sec. III", "Luo et al. (IEEE IoT 2022) Sec. V-C"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires hardware-backed public key in eFuse/ROM for absolute root-of-trust; software fallback validates against immutable keystore."
    ),
    "SEC-L1-02": SecurityProblemDef(
        problem_id="SEC-L1-02",
        layer=1,
        title="Payload Tampering & Cryptographic Hash Verification Failure",
        security_objective="Detect any unauthorized modification, corruption, or injection within the firmware binary.",
        threat_failure_mode="Attacker modifies binary bytes (e.g. flipping privilege flags or patching jump addresses) during transport or in staging memory.",
        countermeasure="Cryptographic SHA-256 digest recalculation and comparison against the manifest hash prior to flash programming.",
        implementation_module="backend/layers/layer1_secure_boot.py::verify_payload_integrity",
        test_id="test_l1_02_payload_tamper",
        research_citations=["Fanjas et al. (DFT 2023) Sec. III-C", "Luo et al. (IEEE IoT 2022) Sec. V-C"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Hash checking is computationally bounded on 8-bit MCUs (ATmega328P); offloaded to hardware cryptoaccelerator on SAM L11 / ESP32."
    ),
    "SEC-L1-03": SecurityProblemDef(
        problem_id="SEC-L1-03",
        layer=1,
        title="Signature Validation Failure (Fanjas V3 Certificate 0 Model)",
        security_objective="Reject packages where the cryptographic digital signature does not mathematically verify against the payload hash.",
        threat_failure_mode="Fault injection or algorithmic flaw bypasses certificate signature checking, accepting an invalid certificate 0.",
        countermeasure="Constant-time RSA/ECDSA signature verification with dual-check status enforcement and explicit error trapping.",
        implementation_module="backend/layers/layer1_secure_boot.py::verify_signature_rsa_ecdsa",
        test_id="test_l1_03_signature_failure",
        research_citations=["Fanjas et al. (DFT 2023) Sec. IV-A & V-B", "Wiersma & Pareja (FDTC 2017) Sec. II"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Pure software signature verification is vulnerable to precise clock/EM glitches unless implemented with complementary condition branches."
    ),
    "SEC-L1-04": SecurityProblemDef(
        problem_id="SEC-L1-04",
        layer=1,
        title="Replay of Stale Valid Update Request",
        security_objective="Prevent adversaries from re-transmitting previously authorized update payloads to induce state desynchronization.",
        threat_failure_mode="Attacker captures legitimate firmware update transmission and replays it over the network or bus at a later date.",
        countermeasure="Monotonic transaction nonce and session-bound timestamp challenge verification on update start handshake.",
        implementation_module="backend/layers/layer1_secure_boot.py::check_update_replay",
        test_id="test_l1_04_replay_attack",
        research_citations=["Luo et al. (IEEE IoT 2022) Table I", "Sensors (2023)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires real-time clock or monotonically increasing state counter preserved across power loss."
    ),
    "SEC-L1-05": SecurityProblemDef(
        problem_id="SEC-L1-05",
        layer=1,
        title="Firmware Downgrade & Anti-Rollback Policy Enforcement",
        security_objective="Prohibit the flashing of authentic, signed older firmware versions that contain known unpatched vulnerabilities.",
        threat_failure_mode="Attacker downgrades device to an older legitimate firmware (v1.0.0) containing a known buffer overflow or logic bug.",
        countermeasure="Anti-rollback enforcement comparing package version against a monotonic hardware counter in secure non-volatile memory.",
        implementation_module="backend/layers/layer1_secure_boot.py::enforce_anti_rollback",
        test_id="test_l1_05_anti_rollback",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. V-F & VII-B", "TI OTA Whitepaper"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="If hardware OTP fuses are exhausted, monotonic counter falls back to wear-leveled flash blocks protected by DAL/MPU."
    ),
    "SEC-L1-06": SecurityProblemDef(
        problem_id="SEC-L1-06",
        layer=1,
        title="Malformed / Incomplete Update Manifest & Header Parsing",
        security_objective="Ensure firmware parser is resilient against buffer overflows, invalid offsets, and integer underflows during header parsing.",
        threat_failure_mode="Attacker sends an image with corrupt magic bytes, negative chunk sizes, or out-of-bounds flash target offsets, crashing the bootloader.",
        countermeasure="Strict length-bounded manifest validation and sanitization prior to allocating staging buffers or decoding fields.",
        implementation_module="backend/layers/layer1_secure_boot.py::parse_manifest",
        test_id="test_l1_06_malformed_manifest",
        research_citations=["ICOIN (2022)", "Luo et al. (IEEE IoT 2022) Sec. IV-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Parser must execute in unprivileged isolation or with strict memory bounds."
    ),
    "SEC-L1-07": SecurityProblemDef(
        problem_id="SEC-L1-07",
        layer=1,
        title="Unsupported Hardware Target / Architecture Mismatch",
        security_objective="Prevent accidental or malicious installation of firmware compiled for an incompatible target MCU or PCB revision.",
        threat_failure_mode="Flashing AVR ATmega328P firmware onto an ESP32 or wrong pinout revision, causing pin contention or permanent hardware latch-up.",
        countermeasure="Mandatory hardware target ID and board revision compatibility checks encoded in signed manifest header.",
        implementation_module="backend/layers/layer1_secure_boot.py::verify_target_hardware",
        test_id="test_l1_07_hardware_mismatch",
        research_citations=["Engineering Recommendation", "Luo et al. (IEEE IoT 2022) Sec. II-B"],
        evidence_type="ENGINEERING_INFERENCE",
        limitation_notes="Requires immutable PCB revision ID pin straps or factory-burned hardware IDs."
    ),
    "SEC-L1-08": SecurityProblemDef(
        problem_id="SEC-L1-08",
        layer=1,
        title="Interrupted / Truncated Chunked OTA Transfer",
        security_objective="Maintain system availability when network drops or power failure interrupts firmware chunk reception mid-stream.",
        threat_failure_mode="Partial upload leaves flash in corrupted half-written state, bricking device on subsequent reboot.",
        countermeasure="Staging scratch buffer with transactional commit and dual-stage CRC verification; golden image remains active until final commit.",
        implementation_module="backend/layers/layer1_secure_boot.py::handle_chunked_ota",
        test_id="test_l1_08_truncated_ota",
        research_citations=["Sensors (2023)", "ICOIN (2022)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Staging area requires either dedicated external SPI flash or dual internal flash partitions."
    ),
    "SEC-L1-09": SecurityProblemDef(
        problem_id="SEC-L1-09",
        layer=1,
        title="Unauthorized Update Requestor / Missing Transport Authentication",
        security_objective="Restrict firmware update initiation endpoints strictly to authenticated operators and administrative consoles.",
        threat_failure_mode="Unauthenticated device on the local network or bus sends an OTA trigger command, staging malicious firmware.",
        countermeasure="Mutual TLS / bearer authorization token validation on the update initiation endpoint before accepting any chunks.",
        implementation_module="backend/layers/layer1_secure_boot.py::authenticate_requestor",
        test_id="test_l1_09_unauthorized_requestor",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. III-E & V-A"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Microcontrollers acting as peripheral bus nodes require session challenge-response over UART/SPI."
    ),
    "SEC-L1-10": SecurityProblemDef(
        problem_id="SEC-L1-10",
        layer=1,
        title="Dual-Bank Safe Recovery & Inconsistent State Rollback",
        security_objective="Guarantee automatic fallback to the known-good 'Golden' firmware bank if newly activated firmware crashes during boot.",
        threat_failure_mode="Activated firmware passes static signature checks but enters bootloop or panic state upon executing hardware init.",
        countermeasure="Dual-bank execution with hardware watchdog boot-grace timer; rollback to Bank A if Bank B fails to assert health status.",
        implementation_module="backend/layers/layer1_secure_boot.py::activate_firmware_dual_bank",
        test_id="test_l1_10_safe_recovery_rollback",
        research_citations=["Luo et al. (IEEE IoT 2022) Fig. 6", "ICOIN (2022)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires minimum flash capacity to store two full executable partitions."
    ),

    # -------------------------------------------------------------
    # LAYER 2: Software-Based Fault Tolerance and Fault Response (10 Problems)
    # -------------------------------------------------------------
    "SEC-L2-01": SecurityProblemDef(
        problem_id="SEC-L2-01",
        layer=2,
        title="Unexpected Target-State Corruption & Invariant Assertion",
        security_objective="Detect register bit-flips and state corruptions caused by transient voltage or EM disturbances during execution.",
        threat_failure_mode="Transient glitch flips register bits (e.g. state variable 0x00 -> 0x01), corrupting execution state without CPU trap.",
        countermeasure="Software invariant assertions and redundant shadow state validation across critical execution milestones.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::check_state_invariants",
        test_id="test_l2_01_state_corruption",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. IV", "Fanjas et al. (FDTC 2024) Table I"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Increases execution time by ~12-18% due to redundant state checks."
    ),
    "SEC-L2-02": SecurityProblemDef(
        problem_id="SEC-L2-02",
        layer=2,
        title="Instruction-Skip Behavior (F1/F2 Models)",
        security_objective="Prevent attackers from skipping critical instructions (decrement, sub, security check) via power/EM glitching.",
        threat_failure_mode="Single clock/voltage glitch causes CPU pipeline to fetch NOP or skip decrement instruction, altering loop counters.",
        countermeasure="Dual-counter unrolled execution with cross-counter equality assertions (w0 == w1) and loop termination tripwires.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::unroll_loop_with_detection",
        test_id="test_l2_02_instruction_skip_f1_f2",
        research_citations=["Fanjas et al. (FDTC 2024) Algorithm 1 & Table I", "Wiersma & Pareja (FDTC 2017) Sec. IV-A"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Hardware lockstep is only partially effective against EM glitches (Wiersma 2017 Table II); software dual-checks provide secondary defense."
    ),
    "SEC-L2-03": SecurityProblemDef(
        problem_id="SEC-L2-03",
        layer=2,
        title="Conditional Branch Hijacking (F3/F4 Models & Auth Bypass)",
        security_objective="Ensure conditional authentication branches cannot be forced into unauthorized execution paths by single-instruction skips.",
        threat_failure_mode="Glitching the comparison instruction (cmp) or branch (beq/bne) causes execution of authenticated branch without credentials.",
        countermeasure="Complementary condition evaluation: checking `(flag == TARGET) && (flag_inv == ~TARGET)` with random delay jitter.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::secure_conditional_branch",
        test_id="test_l2_03_branch_hijack_auth",
        research_citations=["Wiersma & Pareja (FDTC 2017) Listing 2 & Sec. IV-B", "Fanjas et al. (FDTC 2024) Table I (F.3/F.4)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="A multi-glitch attack timed exactly across both complementary evaluations can theoretically succeed if delay is non-randomized."
    ),
    "SEC-L2-04": SecurityProblemDef(
        problem_id="SEC-L2-04",
        layer=2,
        title="Communication Bus Glitch & Frame Interruption",
        security_objective="Prevent corrupted or interrupted bus frames from being processed as valid commands by the target.",
        threat_failure_mode="Transient noise on UART/I2C/SPI lines flips bits or truncates packets, leading to malformed command execution.",
        countermeasure="Framed packet protocol with preamble, length check, sequence index, payload CRC-16, and post-frame delimiter.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::handle_uart_frame",
        test_id="test_l2_04_bus_glitch_parity",
        research_citations=["Fanjas et al. (FDTC 2024) Sec. IV-A", "Sensors (2023)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Adds 4 bytes of overhead per serial frame."
    ),
    "SEC-L2-05": SecurityProblemDef(
        problem_id="SEC-L2-05",
        layer=2,
        title="Malformed, Duplicated, or Out-of-Order Telemetry",
        security_objective="Maintain deterministic ordering and reject duplicated or replayed commands across device telemetry channels.",
        threat_failure_mode="Adversary captures and injects past command frames or bus reflection duplicates command triggers.",
        countermeasure="Sliding sequence window (size=64) tracking received sequence IDs; strictly rejecting duplicate or stale sequence numbers.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::validate_sequence_window",
        test_id="test_l2_05_sequence_window",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. II", "Luo et al. (IEEE IoT 2022) Table I"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Window wraps after 2^32 packets; requires atomic sequence counter."
    ),
    "SEC-L2-06": SecurityProblemDef(
        problem_id="SEC-L2-06",
        layer=2,
        title="Watchdog Reset & Hang Containment",
        security_objective="Guarantee automatic reset and containment when CPU execution stalls or enters an infinite loop following a glitch.",
        threat_failure_mode="Glitch vectors CPU into unmapped memory or invalid loop, causing persistent denial of service.",
        countermeasure="Independent hardware Watchdog Timer (WDT) serviced only after all subsystem invariant checks pass.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::monitor_watchdog",
        test_id="test_l2_06_watchdog_hang",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. VII-D-1", "Ganssle (2012)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Watchdog timeout period must exceed longest legitimate cryptographic computation."
    ),
    "SEC-L2-07": SecurityProblemDef(
        problem_id="SEC-L2-07",
        layer=2,
        title="Inconsistent Authorization State Transition",
        security_objective="Ensure state transitions (e.g. UNVERIFIED -> AUTHORIZED) are atomic and resistant to mid-transition interruption.",
        threat_failure_mode="A glitch during state assignment leaves the target in an ambiguous state where security controls are disabled prematurely.",
        countermeasure="Two-phase commit state machine with transaction tokens and rollback on mid-flight exception.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::atomic_state_transition",
        test_id="test_l2_07_inconsistent_auth_state",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. V", "Luo et al. (IEEE IoT 2022) Sec. IV-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires atomic word writes in SRAM."
    ),
    "SEC-L2-08": SecurityProblemDef(
        problem_id="SEC-L2-08",
        layer=2,
        title="Missing Fault-Detection Events & Telemetry Gap Monitoring",
        security_objective="Detect silent failure or bus jamming where telemetry ceases without an explicit crash notice.",
        threat_failure_mode="Attacker disconnects telemetry line or jams transceiver; backend remains oblivious to target compromise.",
        countermeasure="Continuous heartbeat monitoring with max-cadence threshold; missing 3 consecutive heartbeats escalates risk to HIGH.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::check_telemetry_cadence",
        test_id="test_l2_08_telemetry_gap",
        research_citations=["Wiersma & Pareja (FDTC 2017) Table II", "Sensors (2023)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires background timer thread in backend monitoring bridge."
    ),
    "SEC-L2-09": SecurityProblemDef(
        problem_id="SEC-L2-09",
        layer=2,
        title="Unverified Recovery State & Post-Fault Quarantine",
        security_objective="Prevent compromised or glitch-corrupted targets from resuming normal operations without verifying integrity.",
        threat_failure_mode="After a fault triggers reset, target boots directly into operational mode while SRAM or registers retain corrupted data.",
        countermeasure="Quarantine mode enforcement requiring comprehensive POST (Power-On Self-Test) diagnostic checks before releasing I/O.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::quarantine_and_diagnose",
        test_id="test_l2_09_post_fault_quarantine",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. VII Recommendations"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Quarantine state slightly extends boot duration (+45ms)."
    ),
    "SEC-L2-10": SecurityProblemDef(
        problem_id="SEC-L2-10",
        layer=2,
        title="Failure to Fail Closed & Emergency Lockdown",
        security_objective="Guarantee that upon unhandled faults or persistent attack, target shuts down sensitive outputs rather than failing open.",
        threat_failure_mode="Software exception handler defaults to permissive return, allowing unauthorized memory dump or actuator activation.",
        countermeasure="Fail-closed emergency shutdown: immediate zeroization of session keys, disabling transmitter drivers, and hardware latch.",
        implementation_module="backend/layers/layer2_fault_tolerance.py::fail_closed_emergency",
        test_id="test_l2_10_fail_closed_lockdown",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. VII", "NIST SP 800-88"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires manual power cycle or authenticated command to recover from hardware latch."
    ),

    # -------------------------------------------------------------
    # LAYER 3: Silicon Lockdown and Device Protection (10 Problems)
    # -------------------------------------------------------------
    "SEC-L3-01": SecurityProblemDef(
        problem_id="SEC-L3-01",
        layer=3,
        title="Unauthorized Hardware Configuration Changes (BOCOR/UROW Fuses)",
        security_objective="Prevent unauthorized software from altering critical security fuses and boot configurations in silicon.",
        threat_failure_mode="Malware running on device attempts to overwrite Non-Volatile Memory (NVM) configuration rows to disable security.",
        countermeasure="Silicon fuse lock: BOCOR and UROW rows locked to DAL2 access privilege; changes rejected and require full chip erase.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::verify_fuse_protection",
        test_id="test_l3_01_fuse_protection",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. II-B & V-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Hardware specific to ARM Cortex-M23 (SAM L11); ATmega328P uses high-voltage fuse programming lockout."
    ),
    "SEC-L3-02": SecurityProblemDef(
        problem_id="SEC-L3-02",
        layer=3,
        title="Inadequate Device-Access Restriction (DAL Tiering)",
        security_objective="Enforce strict Debugger Access Level (DAL) hierarchy to prevent unauthenticated memory dumping.",
        threat_failure_mode="External debugger connects to SWD port and reads out sensitive firmware or cryptographic keys without credentials.",
        countermeasure="Debugger Access Level 0 (DAL0) lockdown; transitioning to DAL1/DAL2 requires 128-bit Chip Erase Key (CEKEY).",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::enforce_dal_access",
        test_id="test_l3_02_dal_tiering",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. V-B & VII-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Level transition strictly executes ChipErase_ALL, ensuring secret assets are destroyed prior to debugger attachment."
    ),
    "SEC-L3-03": SecurityProblemDef(
        problem_id="SEC-L3-03",
        layer=3,
        title="SWD / JTAG Debug Port Exposure in Production",
        security_objective="Permanently close or cryptographically protect debug interfaces on production units deployed in the field.",
        threat_failure_mode="Attacker physically probes JTAG/SWD test pads on PCB to gain interactive control of CPU execution.",
        countermeasure="Hardware JTAG disable fuse blown during factory provisioning; physical pin disconnect and DPA power profiling monitoring.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::audit_debug_port_lock",
        test_id="test_l3_03_debug_port_lock",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. V & VI", "Luo et al. (IEEE IoT 2022) Sec. III-A"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Wiersma et al. showed JTAG lock can be attacked via voltage/EM glitches; combining with fuse blow mitigates ROM timing bypass."
    ),
    "SEC-L3-04": SecurityProblemDef(
        problem_id="SEC-L3-04",
        layer=3,
        title="Flash Readback Protection Bypass & Lock Bit Tampering",
        security_objective="Prohibit external programmers from reading out internal flash memory contents across all programming modes.",
        threat_failure_mode="Attacker places MCU in parallel programming or ISP mode to dump proprietary IP and encryption keys.",
        countermeasure="Flash Security Lock Bits (ATmega328P LB1=0, LB2=0) programmed to prohibit memory read commands via ISP.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::verify_flash_lock_bits",
        test_id="test_l3_04_flash_readback_protect",
        research_citations=["ATmega328P Datasheet", "Wiersma & Pareja (FDTC 2017) Sec. V-B"],
        evidence_type="HARDWARE_MEASURED",
        limitation_notes="Can only be reset by full chip erase which wipes all flash and EEPROM contents."
    ),
    "SEC-L3-05": SecurityProblemDef(
        problem_id="SEC-L3-05",
        layer=3,
        title="Security Policy Misconfiguration (RXN / DXN Permissions)",
        security_objective="Prevent code execution from data RAM and data flash to defeat stack and heap buffer overflow code injection.",
        threat_failure_mode="Attacker exploits stack buffer overflow to inject shellcode into SRAM and diverts PC to execute it.",
        countermeasure="Hardware Execute-Never policies: RAM Execute Never (RXN=1) and Data Flash Execute Never (DXN=1) in silicon fuses.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::enforce_memory_execution_policy",
        test_id="test_l3_05_rxn_dxn_policy",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. V-D & VII-B (DXN/RXN)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Defeats code injection; return-oriented programming (ROP) requires additional CFI / iASLR defenses."
    ),
    "SEC-L3-06": SecurityProblemDef(
        problem_id="SEC-L3-06",
        layer=3,
        title="Missing Boot-Time Device Integrity Verification",
        security_objective="Verify hardware configuration integrity before allowing execution of application code.",
        threat_failure_mode="Glitching during boot ROM execution causes skip of fuse verification, leaving device in unhardened default state.",
        countermeasure="Hardware Boot ROM performs cryptographic digest check of BOCOR row and secure bootloader before passing execution.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::verify_boot_integrity",
        test_id="test_l3_06_boot_integrity",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. V-C", "Fanjas et al. (DFT 2023) Sec. IV-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Hardware boot ROM is immutable; must fail into halt loop if fuse digest mismatch is detected."
    ),
    "SEC-L3-07": SecurityProblemDef(
        problem_id="SEC-L3-07",
        layer=3,
        title="Anti-Rollback Enforcement Gaps in Silicon OTP Storage",
        security_objective="Ensure version rollback protection cannot be cleared by power cycles or software manipulation.",
        threat_failure_mode="Software-managed version numbers in normal flash are wiped or restored to previous backups.",
        countermeasure="Hardware One-Time Programmable (OTP) monotonic fuse array; bits can only be burned (0->1) and never reversed.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::check_otp_monotonic_counter",
        test_id="test_l3_07_otp_monotonic_counter",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. V-B", "Luo et al. (IEEE IoT 2022) Sec. V-F"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Total counter updates bounded by physical OTP bit field size (e.g. 32 to 128 updates)."
    ),
    "SEC-L3-08": SecurityProblemDef(
        problem_id="SEC-L3-08",
        layer=3,
        title="Insecure Provisioning & Illegal Lifecycle Transitions",
        security_objective="Enforce unidirectional progression of device lifecycle (Manufacturing -> Provisioned -> Field Deployed -> Decommissioned).",
        threat_failure_mode="Attacker forces device back into Manufacturing or Unlocked lifecycle state to regain diagnostic privileges.",
        countermeasure="State machine locked by OTP silicon registers; irreversible state progression enforced by on-chip logic.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::validate_lifecycle_state",
        test_id="test_l3_08_lifecycle_transition",
        research_citations=["Wiersma & Pareja (FDTC 2017) Sec. V-B", "Luo et al. (IEEE IoT 2022) Sec. III-A"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Decommissioning blows permanent security fuse, disabling all execution."
    ),
    "SEC-L3-09": SecurityProblemDef(
        problem_id="SEC-L3-09",
        layer=3,
        title="Failure to Detect Unauthorized Hardware State Transitions",
        security_objective="Detect out-of-specification electrical conditions (under-voltage, clock glitch, extreme temperature) used in fault attacks.",
        threat_failure_mode="Attacker lowers supply voltage to 730mV or injects fast transients to induce timing errors (Fanjas 2024 Table II).",
        countermeasure="Internal Brown-Out Detector (BOD) and Clock Failure Detection (CFD) circuitry triggering immediate hardware reset.",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::monitor_hardware_tamper",
        test_id="test_l3_09_hardware_tamper",
        research_citations=["Fanjas et al. (FDTC 2024) Sec. IV-D & Table II", "Sensors (2023)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="BOD reaction time (~1-2us) is slower than nanosecond glitches; requires decoupling capacitor placement defense."
    ),
    "SEC-L3-10": SecurityProblemDef(
        problem_id="SEC-L3-10",
        layer=3,
        title="Inaccurate / Spoofed Lockdown Status Reporting",
        security_objective="Ensure remote monitoring systems receive authentic, untampered proof of hardware lockdown status.",
        threat_failure_mode="Compromised target software reports 'LOCKED' status to backend while debug interface remains open.",
        countermeasure="Hardware attestation report signed by internal private key held in secure crypto-coprocessor (ATECC608A / TrustZone).",
        implementation_module="backend/layers/layer3_silicon_lockdown.py::generate_lockdown_attestation",
        test_id="test_l3_10_attestation_spoof",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. V-A & VIII", "Abera et al. (2016)"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires asymmetric hardware key isolated from rich execution environment."
    ),

    # -------------------------------------------------------------
    # LAYER 4: Cryptographic Sanitization and Data Lifecycle (10 Problems)
    # -------------------------------------------------------------
    "SEC-L4-01": SecurityProblemDef(
        problem_id="SEC-L4-01",
        layer=4,
        title="Weak Dataset Key Generation & Insufficient Entropy",
        security_objective="Guarantee that all cryptographic keys are generated using true physical entropy to prevent key predictability.",
        threat_failure_mode="Pseudorandom generator initialized with predictable seed (e.g. boot time), allowing attacker to deduce secret keys.",
        countermeasure="Hardware True Random Number Generator (TRNG) / NIST SP 800-90A CSPRNG with continuous health tests.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::generate_dataset_key",
        test_id="test_l4_01_key_generation_entropy",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. II-B", "NIST SP 800-90A"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="TRNG entropy health tests must abort key generation if repetitive patterns are detected."
    ),
    "SEC-L4-02": SecurityProblemDef(
        problem_id="SEC-L4-02",
        layer=4,
        title="Unauthenticated Encryption & Nonce Reuse Vulnerability",
        security_objective="Prevent keystream recovery and forgery in symmetric dataset encryption.",
        threat_failure_mode="Reusing the same 96-bit Initialization Vector (IV) under AES-GCM allows mathematical recovery of authentication key and plaintext.",
        countermeasure="Strict AES-256-GCM authenticated encryption with monotonic 96-bit nonce manager and historical collision cache.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::encrypt_dataset_aes_gcm",
        test_id="test_l4_02_aes_gcm_nonce_reuse",
        research_citations=["NIST SP 800-38D", "Luo et al. (IEEE IoT 2022) Sec. III-D"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Nonce cache bounds tracking to active session; persisted epoch counters prevent post-reboot collisions."
    ),
    "SEC-L4-03": SecurityProblemDef(
        problem_id="SEC-L4-03",
        layer=4,
        title="Ciphertext & Authentication Tag Tampering",
        security_objective="Detect any alteration to encrypted telemetry or stored records before attempting data processing.",
        threat_failure_mode="Bit-flipping in ciphertext or tag truncation bypasses data integrity checks, resulting in forged record processing.",
        countermeasure="128-bit GMAC authentication tag verification; immediate fail-stop upon tag mismatch before passing buffer to application.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::decrypt_dataset_aes_gcm",
        test_id="test_l4_03_tag_tampering",
        research_citations=["NIST SP 800-38D", "Luo et al. (IEEE IoT 2022) Sec. IV-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Decryption and authentication are performed in a single authenticated pass to avoid padding oracle attacks."
    ),
    "SEC-L4-04": SecurityProblemDef(
        problem_id="SEC-L4-04",
        layer=4,
        title="Unauthorized Sanitization Request / Missing Operator Privilege",
        security_objective="Prevent unauthorized entities from triggering data purge or key destruction commands.",
        threat_failure_mode="Malicious network actor invokes sanitization API, causing unauthorized permanent loss of operational logs.",
        countermeasure="Cryptographically signed authorization token (dual-control operator signature) required for sanitization commands.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::authorize_sanitization",
        test_id="test_l4_04_unauthorized_sanitization",
        research_citations=["NIST SP 800-88 Rev. 1 Sec. 2.4", "Luo et al. (IEEE IoT 2022) Sec. III-A"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires root administrator public key installed during provisioning."
    ),
    "SEC-L4-05": SecurityProblemDef(
        problem_id="SEC-L4-05",
        layer=4,
        title="Key Rotation Failure & Key Wearout",
        security_objective="Enforce proactive retirement of encryption keys before reaching cryptographic lifetime or invocation limits.",
        threat_failure_mode="Using a single key across millions of messages increases side-channel leakage risk and vulnerability to cryptanalysis.",
        countermeasure="Automated epoch-based key rotation; generation of Key V2, re-wrapping dataset headers, and retirement of Key V1.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::rotate_dataset_key",
        test_id="test_l4_05_key_rotation",
        research_citations=["NIST SP 800-57 Part 1", "Wiersma & Pareja (FDTC 2017) Sec. II"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Existing stored datasets must either be re-encrypted or key version table retained in secure storage."
    ),
    "SEC-L4-06": SecurityProblemDef(
        problem_id="SEC-L4-06",
        layer=4,
        title="Key Revocation Enforcement & Immediate Access Revocation",
        security_objective="Ensure compromised or retired keys are instantaneously invalidated and barred from further cryptographic use.",
        threat_failure_mode="Device continues encrypting or decrypting with a key known to be compromised, leaking subsequent data.",
        countermeasure="Real-time revocation list check inside the cryptographic engine; revoked keys return ACCESS_DENIED immediately.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::revoke_dataset_key",
        test_id="test_l4_06_key_revocation",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. III-E", "NIST SP 800-57"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Revocation status must be consulted before every encryption/decryption invocation."
    ),
    "SEC-L4-07": SecurityProblemDef(
        problem_id="SEC-L4-07",
        layer=4,
        title="Cross-Dataset Key Separation & Tenant Isolation",
        security_objective="Enforce strict cryptographic boundaries between distinct datasets, tenants, and security domains.",
        threat_failure_mode="Key assigned to Telemetry Dataset A is accidentally or maliciously used to decrypt Sensitive Config Dataset B.",
        countermeasure="Cryptographic domain separation: dataset ID and tenant context bound into AES-GCM Additional Authenticated Data (AAD).",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::verify_dataset_isolation",
        test_id="test_l4_07_cross_dataset_isolation",
        research_citations=["Luo et al. (IEEE IoT 2022) Sec. V-A & VII-B", "NIST SP 800-38D"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Ensures cross-dataset ciphertext injection fails authentication tag verification even if keys are identical."
    ),
    "SEC-L4-08": SecurityProblemDef(
        problem_id="SEC-L4-08",
        layer=4,
        title="Dataset Deletion & Key Lifecycle Inconsistency",
        security_objective="Ensure dataset deletion is atomic across index entries, memory buffers, and key-wrapping structures.",
        threat_failure_mode="File records are deleted from index but decryption key remains cached in RAM or flash, enabling forensic recovery.",
        countermeasure="Atomic purge lifecycle: synchronous deletion of directory references, memory zeroization, and key wrapping block destruction.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::atomic_dataset_purge",
        test_id="test_l4_08_lifecycle_inconsistency",
        research_citations=["NIST SP 800-88 Rev. 1 Sec. 2.4", "Luo et al. (IEEE IoT 2022) Sec. IV-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Requires filesystem and key management coordination to prevent orphan keys."
    ),
    "SEC-L4-09": SecurityProblemDef(
        problem_id="SEC-L4-09",
        layer=4,
        title="Cryptographic Erasure (Crypto-Shredding) & Memory Zeroization",
        security_objective="Render encrypted target data permanently unrecoverable in milliseconds by destroying the master decryption key.",
        threat_failure_mode="Adversary seizes decommissioned or stolen device and extracts raw NAND/flash contents via chip-off forensics.",
        countermeasure="Cryptographic erasure (NIST SP 800-88): secure multipass zeroization of master key in RAM and secure NVM, rendering ciphertext irreversibly unrecoverable.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::crypto_shred_dataset",
        test_id="test_l4_09_crypto_shredding_zeroize",
        research_citations=["NIST SP 800-88 Rev. 1 Sec. 4.3", "Luo et al. (IEEE IoT 2022) Sec. V-A"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Physical media cells retain ciphertext; security relies mathematically on 256-bit AES cipher strength."
    ),
    "SEC-L4-10": SecurityProblemDef(
        problem_id="SEC-L4-10",
        layer=4,
        title="Post-Erasure Recovery Attempts & Stale-Reference Handling",
        security_objective="Ensure all post-erasure read or recovery attempts strictly fail with documented error status and zero data leakage.",
        threat_failure_mode="Application attempts to read dangling dataset pointer after erasure, returning stale in-memory buffers or partial reads.",
        countermeasure="Dangling handle trap: invalidating dataset handles, clearing read cache, and returning formal PERMANENTLY_PURGED status.",
        implementation_module="backend/layers/layer4_crypto_lifecycle.py::attempt_post_erasure_read",
        test_id="test_l4_10_post_erasure_recovery",
        research_citations=["NIST SP 800-88 Rev. 1 Sec. 4.3", "Luo et al. (IEEE IoT 2022) Sec. IV-B"],
        evidence_type="RESEARCH_VALIDATED",
        limitation_notes="Traps both API-level dereferencing and low-level cache buffers."
    ),
}

def get_problem(problem_id: str) -> SecurityProblemDef:
    return PROBLEM_CATALOG[problem_id]

def get_problems_by_layer(layer: int) -> List[SecurityProblemDef]:
    return [p for p in PROBLEM_CATALOG.values() if p.layer == layer]

