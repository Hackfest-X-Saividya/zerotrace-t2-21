# Layer 4 — Cryptographic Sanitization (NIST SP 800-88 Rev 1)

## 1. Objective
Layer 4 demonstrates **Cryptographic Erase (CE)** as defined in **NIST SP 800-88 Section 4.7**:
Sanitizing sensitive data by destroying or zeroizing the dedicated cryptographic keys required to decrypt target ciphertext records.

Mapped to **NIST CSF 2.0**:
- **RS.MI-02**: Incident Mitigation & Media Sanitization

---

## 2. Cryptographic Architecture
- **Encryption Algorithm**: AES-256-GCM (Galois/Counter Mode).
- **Key Generation**: 256-bit cryptographically secure random key (DEK) via `os.urandom(32)`.
- **Nonce**: 96-bit unique nonce (12 bytes) generated freshly per encryption operation.
- **Authentication**: 128-bit authentication tag appended to ciphertext.
- **Key Management**: Keys reside in a dedicated in-memory Key Registry.
- **Zeroization**: When sanitization is authorized, the key memory buffer is explicitly overwritten with zeros (`memset` pattern) and unlinked from the registry.

---

## 3. Demonstration Lifecycle

1. **Dataset Encryption**: Red Team requests creation of synthetic dataset `DS-XXXX`. A 256-bit DEK is generated and stored in the registry.
2. **Pre-Sanitization Verification**: Blue Team tests normal decryption. Ciphertext is verified accessible.
3. **Tampered Ciphertext Negative Test**: A bit flip in ciphertext is rejected via GCM authentication tag failure (`AUTHENTICATION_FAILED`).
4. **Unauthorized Sanitization Negative Test**: Attempt to sanitize without valid operator authorization is blocked. Key remains active.
5. **Authorized Sanitization**: Operator confirms sanitization. Key memory is zeroized and deleted from registry.
6. **Post-Sanitization Verification**: Decryption is re-attempted. Fails specifically with `CRYPTOGRAPHICALLY_UNRECOVERABLE` because the key is destroyed.

---

## 4. Honest Limitations
ZeroTrace explicitly documents that in-memory volatile zeroization is a software demonstration of Cryptographic Erase. It does not prove physical forensic eradication from raw NAND flash blocks subject to flash translation layers (FTL) or wear-leveling.
