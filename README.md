# 🛡️ Sentinel Chain — AI-Powered Cyber Defense & Blockchain Platform

Sentinel Chain is an enterprise cyber defense platform uniting autonomous AI threat detection with a post-quantum cryptographic blockchain evidence assurance ledger.

---

## ⚡ Quick Start

### 1. Launch Platform (Windows)
Double-click `run.bat` or run in terminal:
```powershell
cd C:\Users\UTKARSH\.vscode\sentinel_chain
python server.py
```

- **Web Application:** [http://localhost:8000](http://localhost:8000)
- **Interactive REST API Explorer:** [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- **Health Check:** [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Live Threat Stream (SSE):** `GET /api/threats/stream`

### 2. Run Test Suite
```powershell
python test_api.py
```
> **17/17 (100%) tests passing** verifying all REST endpoints, SHA-256 block hashing, Merkle root verification, and AI entropy heuristics.

---

## 🔐 Default Access Credentials

All seeded accounts use password: `Sentinel@2026!`

| Name | Role | Email | Status |
| :--- | :--- | :--- | :--- |
| **Riya Singh** | Administrator | `riya.singh@sentinelchain.io` | Active (MFA) |
| **John Doe** | SOC Analyst | `john.doe@sentinelchain.io` | Active (MFA) |
| **Jane Smith** | SOC Analyst | `jane.smith@sentinelchain.io` | Active (MFA) |
| **Arman Verma**| SOC Analyst | `arman.verma@sentinelchain.io` | Active |
| **Meera Iyer** | Auditor | `meera.iyer@sentinelchain.io` | Active (MFA) |

*Universal demo 2FA code:* `123456`

---

## 🏗️ Architecture

```
                                  [ Netlify / Local Web SPA ]
                                               │
                                               ▼
                              [ Multi-Threaded HTTP & SSE Server ]
                                      (server.py :8000)
                                               │
               ┌───────────────────────┬───────┴───────────────┬────────────────────────┐
               │                       │                       │                        │
               ▼                       ▼                       ▼                        ▼
       [ Authentication ]     [ Live Threats & SOC ]    [ AI Defense Engine ]   [ Blockchain Ledger ]
        - PBKDF2 Hashing       - Ingestion & Triage      - Shannon Entropy       - SHA-256 Hashing
        - Stateless JWT        - Auto-Quarantine         - MITRE ATT&CK Map      - Merkle Root Trees
        - 2FA OTP Codes        - SSE Live Streaming      - Auto Remediation      - Tamper Auditing
               │                       │                       │                        │
               └───────────────────────┴───────┬───────────────┴────────────────────────┘
                                               │
                                               ▼
                                   [ Thread-Safe SQLite DB ]
                                  (data/sentinel_chain.db)
```

---

## 📡 REST API Reference

### Authentication & Users
- `POST /api/auth/login` — Login with email and password, receives JWT token.
- `POST /api/auth/register` — Register a new analyst account.
- `GET /api/auth/me` — Return profile for current Bearer token.
- `POST /api/auth/verify-2fa` — Verify two-factor OTP code.

### Dashboard & Metrics
- `GET /api/dashboard/stats` — Composite threat score (97/100), detection rate (98.4%), MTTD (4.2m), MTTR (22m), asset count.
- `GET /api/dashboard/threat-trend` — 24-hour threat and incident volume timeline.
- `GET /api/dashboard/attack-types` — Distribution of attacks (Malware, Brute Force, Phishing, Recon, Priv. Escalation, DDoS).
- `GET /api/dashboard/geo-threats` — Global attack coordinates for threat map.
- `GET /api/dashboard/alerts` — Real-time active alerts stream.

### Live Threats & Response
- `GET /api/threats` — Filter by `status`, `severity`, `search`, pagination.
- `GET /api/threats/:id` — Single threat detail.
- `POST /api/threats` — Ingest telemetry sample; automatically computes AI confidence and MITRE technique.
- `PATCH /api/threats/:id` — Update status (`open`, `investigating`, `contained`, `resolved`).
- `POST /api/threats/:id/quarantine` — Trigger automated host isolation on VLAN 999.
- `GET /api/threats/stream` — Real-time Server-Sent Events (SSE) stream.

### Incident Management
- `GET /api/incidents` — List all incidents tickets.
- `GET /api/incidents/:id` — Full incident detail with linked blockchain evidence proof.
- `POST /api/incidents` — Create incident ticket; optionally anchors evidence to ledger.
- `PATCH /api/incidents/:id` — Update status, assigned analyst, or description.
- `POST /api/incidents/:id/actions` — Rapid containment (`anchor_evidence`, `isolate_hosts`, `resolve_incident`).

### Blockchain Evidence Assurance
- `GET /api/blockchain/evidence` — List immutable evidence blocks with digital signatures.
- `GET /api/blockchain/evidence/:id` — Detailed forensic record with Merkle root and block header.
- `POST /api/blockchain/anchor` — Mine a new block and anchor forensic proof to ledger.
- `POST /api/blockchain/verify/:id` — Walk cryptographic chain and verify SHA-256 integrity.
- `GET /api/blockchain/audit-chain` — Audit complete ledger from genesis (block #585220) to tip.
- `GET /api/blockchain/blocks` — List ledger blocks.
- `GET /api/blockchain/peers` — List active validator peer nodes.

### AI Autonomous Defense
- `GET /api/ai/analysis` — AI model detections and predictions inventory.
- `POST /api/ai/analyze-sample` — Instant Shannon entropy calculation, MITRE ATT&CK mapping, confidence score, and remediation playbook for any suspicious log or script.
- `GET /api/ai/models` — Active model benchmarks (GNN, XGBoost, Autoencoder, Isolation Forest).

### Infrastructure, SOC & Intelligence
- `GET /api/assets` — Monitored laptops, servers, databases, and cloud nodes.
- `POST /api/assets/:id/isolate` — Emergency asset network isolation.
- `GET /api/soc/team` — Analyst roster, resolved counts, and performance scores.
- `GET /api/intel/iocs` — Indicators of compromise feed.
- `GET /api/intel/cves` — CVE vulnerability database.
- `POST /api/intel/lookup` — Malicious reputation check for IP, domain, or hash.
- `GET /api/compliance` — SOC 2, ISO 27001, HIPAA, NIST CSF compliance posture.
- `GET /api/audit-logs` — Tamper-evident audit trail with SHA-256 event hashes.

---

## 🚀 Cloud Deployment

### Deploy to Render
The repository includes `render.yaml` and `Procfile`.
1. Push this folder to GitHub.
2. In Render Dashboard, click **New Web Service** and select your repository.
3. Build Command: `echo 'Zero-dependency standard library build'`
4. Start Command: `python server.py`
