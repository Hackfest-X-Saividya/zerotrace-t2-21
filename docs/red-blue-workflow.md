# Red Team & Blue Team Operational Workflow

## 1. Unified Architecture
In ZeroTrace, Red Team and Blue Team are not disconnected pages. They share:
- The authoritative FastAPI backend state.
- The shared event bus and audit trail (`event_service.py`).
- Real-time Server-Sent Events (SSE) stream (`/api/stream`).
- URL query-parameter navigation (`?view=red` and `?view=blue`).

---

## 2. Shared Operational Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Red as Red Team (Dispatch)
    participant Auth as Access Service
    participant API as FastAPI Backend
    participant Event as Event & Audit Bus
    participant Blue as Blue Team (Verifier)

    Red->>Auth: Request Temporary Demo Credential
    Auth-->>Red: Return Token (Displayed Once)
    Red->>API: Dispatch Test Scenario (with Credential ID)
    API->>API: Execute Controlled Defense Logic
    API->>Event: Publish Structured SecurityEvent
    Event-->>Blue: Stream via SSE (/api/stream)
    Blue->>Blue: Independent Postcondition Verification
    Blue->>Event: Record BlueTeamFinding
    Blue-->>Red: Display Correlated Findings & Metrics
```

---

## 3. Scoped Temporary Demonstration Credential

To govern privileged operations in the software test environment, Red Team can generate a temporary token:
- **Label**: `TEMPORARY DEMO ENVIRONMENT CREDENTIAL — NOT A HARDWARE JTAG PASSWORD`
- **Entropy**: 256-bit cryptographically secure random value (`secrets.token_urlsafe(32)`).
- **Storage**: Only the SHA-256 hash is retained in memory.
- **Privacy**: The plaintext token is displayed once upon creation and never exposed in event streams or logs.
- **Safety Policy**: The token cannot authorize physical silicon destruction or irreversible eFuse modification.
