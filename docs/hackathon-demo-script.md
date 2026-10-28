# ZeroTrace — Hackathon Demonstration Script

## Time: 3 to 5 Minutes
## Target Audience: Technical Evaluators, Cybersecurity Judges, Embedded Engineers

---

### Step 1: Context & Problem (0:00 - 0:45)
**Presenter Speaking:**
> "Embedded and IoT devices often suffer from two critical architectural vulnerabilities: insecure firmware updates that accept tampered code, and sensitive cryptographic keys that linger in flash or volatile memory after decommissioning.
> 
> Welcome to **ZeroTrace**: an interactive cyber-physical testbed demonstrating a 4-Layer Zero-Trust Framework for IoT microcontrollers, mapped directly to NIST CSF 2.0.
> 
> Right now, running on this single MacBook, we have a live comparative testbed connected to two physical microcontrollers:
> 1. Target A on the left: an **ESP8266 NodeMCU**, representing a baseline IoT device with seeded, realistic architectural weaknesses.
> 2. Target B on the right: an **ESP32 DevKit**, running our hardened ZeroTrace defensive firmware.
>
> We operate in **Mode A: Hardware Comparative Testbed**. The MacBook sends identical test vectors to both microcontrollers and compares their real defensive decisions side by side."

---

### Step 2: Live Hardware Discovery & Light Theme UI (0:45 - 1:15)
**Presenter Action:**
1. Open dashboard at `http://127.0.0.1:8000`.
2. Point out the top header:
   - Wordmark: `ZeroTrace`
   - Subtitle: `Embedded & IoT Security Testbed`
   - Mode badge: `Mode A: Hardware Comparative` (or `Simulation Engine` when offline)
   - Real-time hardware indicators: `Target A (ESP8266)` and `Target B (ESP32)`
   - Show the theme switcher: toggle between **Light Mode** (clean, crisp, professional default) and **Dark Mode**, then toggle back to Light.
3. Show the **Device Status** tab (`?view=devices`):
   - Highlight the **Scan & Auto-Identify Boards** button.
   - Mention: *"Notice our honest security boundary: we explicitly distinguish physical hardware responses from software simulations, and never claim inline interception when running in comparative Mode A."*

---

### Step 3: One-Click Red Team Campaign (1:15 - 3:00)
**Presenter Action:**
1. Navigate to the **Red Team** tab (`?view=red`).
2. Click the prominent button: **`START RED TEAM CAMPAIGN`**.
3. Watch the real-time progress bar advance through the 10 sequential scenarios:
   `Test X of 10 → Request sent → Target response → Blue validation → Verdict → Evidence saved`
4. Point to the **Live Flow Comparative Pipeline**:
   - Trace the signal flow: `Red Team → Dispatcher → Parallel Targets (ESP8266 vs ESP32) → Blue Team → Evidence Store`.
   - Explain the 5 Layer 1 OTA scenarios as they execute:
     - **L1-01 (Authentic Package):** Both baseline and hardened accept an authentic update.
     - **L1-02 (Payload Tampering):** Baseline accepts a modified payload because it only checks a weak CRC32; Hardened drops the payload immediately because the HMAC-SHA256 signature fails.
     - **L1-03 (Corrupted Authentication Tag):** Hardened traps the bad HMAC tag and halts execution.
     - **L1-04 (Replay Attack):** Baseline re-executes the duplicate update; Hardened catches the duplicate request ID in its session cache and drops it.
     - **L1-05 (Downgrade Exploit):** Baseline rolls back to v0; Hardened's monotonic NVS counter strictly enforces anti-rollback policy.
   - Explain the 5 Layer 4 Cryptographic Lifecycle scenarios as they execute:
     - **L4-01 (Encryption):** Generates dedicated 256-bit AES-GCM key and synthetic dataset.
     - **L4-02 (Verification):** Decrypts and authenticates original synthetic plaintext.
     - **L4-03 (Tampered Tag):** AES-GCM authenticated tag check traps modified ciphertext; no corrupted plaintext is returned.
     - **L4-04 (Unauthorized Wipe):** Rejects key wipe without authorization token.
     - **L4-05 (Sanitization & Zeroization):** Issues authorized token, executes memory zeroization in RAM + metadata unlinking, and proves post-sanitization decryption fails with `CRYPTOGRAPHICALLY_UNRECOVERABLE`.

---

### Step 4: Blue Team Evidence Ledger & Export (3:00 - 3:45)
**Presenter Action:**
1. Navigate to the **Blue Team** tab (`?view=blue`).
2. Point out:
   - Real-time timestamped audit timeline.
   - Explicit evidence levels: `HARDWARE_VERIFIED`, `SOFTWARE_VERIFIED`, `SIMULATED`.
   - Filter buttons: Click `HARDWARE` or `SOFTWARE` to inspect corroborating proof.
   - Clean readable status badges: `ACCEPTED`, `REJECTED_CRYPTO_FAIL`, `REJECTED_DOWNGRADE`, `ZEROIZED_AND_UNLINKED`.
3. Click **`Export Defensive Audit Report (.CSV)`** or **`EXPORT EVIDENCE`** (JSON) to show judges how the entire session can be audited for compliance against NIST CSF 2.0.

---

### Step 5: Test Completion Summary & Honest Disclaimer (3:45 - 4:00)
**Presenter Concluding Statement:**
> "Upon completion of the 10 scenarios, ZeroTrace displays an authoritative summary: 10 executed, verified defenses, 0 silent failures, with complete separation between physical UART evidence and software mock validations.
> 
> As explicitly stated in our disclaimer: controlled comparative tests validate policy compliance for tested vectors; passing tests do not claim universal zero-day immunity.
> 
> ZeroTrace delivers honesty, real embedded hardware verification, and zero-trust security on a single laptop. Thank you, and we'd love to take your questions!"
