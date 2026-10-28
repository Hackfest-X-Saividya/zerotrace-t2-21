# ZeroTrace REST & SSE API Reference

## 1. System & Overview
- `GET /api/health` — Backend health, connected devices, and active layers.
- `GET /api/overview` — Aggregated operational posture, NIST coverage, active credentials, and recent events.
- `GET /api/catalog` — List of all 9 predefined test scenarios and NIST CSF mappings.
- `GET /api/ports` — Discovers active USB serial ports (`/dev/cu.*` or `COM*`).
- `GET /api/stream` — Real-time Server-Sent Events (SSE) telemetry stream.

## 2. Access Management (Temporary Credentials)
- `POST /api/access/issue` — Issues a scoped temporary credential with SHA-256 verifier. Returns plaintext once.
- `POST /api/access/verify` — Validates credential token against stored verifier and required scope.
- `POST /api/access/revoke` — Revokes an active credential immediately.
- `GET /api/access/list` — Lists public metadata of active credentials (without secrets).

## 3. Test Orchestration & Evaluation
- `POST /api/execute-test` — Executes a test scenario (in simulation or real hardware mode).
- `GET /api/results` — Retrieves test evaluation history.
- `GET /api/csf-coverage` — Dynamically computes NIST CSF 2.0 coverage across all 22 categories.
- `GET /api/metrics` — Returns metrics counters (pass, fail, baseline weaknesses, hardened mitigations).
- `POST /api/reset` — Clears in-memory test history and resets counters.
- `GET /api/export-results` — Downloads test evaluation records formatted as CSV.

## 4. Layer-Specific Endpoints
- `POST /api/layer1/update` — Executes Layer 1 OTA update scenarios (`valid`, `tampered`, `downgrade`, etc.).
- `GET /api/layer1/status` — Returns monotonic counter version and golden image state.
- `POST /api/layer2/fault` — Executes Layer 2 SBFT fault scenarios (`consistent`, `inconsistent`, `watchdog`).
- `GET /api/layer2/status` — Returns dual-rail register state and invariant status.
- `POST /api/layer3/audit` — Executes Layer 3 silicon check or debug policy verification.
- `GET /api/layer3/status` — Returns JTAG lockout policy, Secure Boot, and Flash Encryption states.
- `POST /api/layer4/create` — Encrypts a synthetic test dataset using AES-256-GCM.
- `GET /api/layer4/list` — Lists encrypted datasets and DEK states.
- `POST /api/layer4/verify` — Verifies decryption pre-sanitization or failure post-sanitization.
- `POST /api/layer4/sanitize` — Authorizes cryptographic sanitization (zeroizes dedicated DEK in memory).

## 5. Audit & Blue Team
- `GET /api/events` — Query structured security events with layer/severity/evidence filters.
- `GET /api/audit/trail` — Query immutable evaluator audit trail log.
- `GET /api/blue-team/findings` — Query verified Blue Team defensive findings.
