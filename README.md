# ForenSight AI — Digital Forensics Timeline Reconstruction Platform

**Problem Statement: PS 72 | United Nations SDGs: 9, 16, 17**  
*Reconstruct the Truth. Preserve Every Evidence.*

---

## 1. Project Overview

Digital forensic examinations frequently confront fragmented evidence across endpoints, network perimeters, domain controllers, and web proxies. Investigators face severe challenges correlating multi-vendor logs, reconciling clock drift across unsynchronized hosts, and identifying anti-forensic timestomping attempts without introducing bias.

**ForenSight AI** is a full-stack digital forensics timeline reconstruction platform engineered with **read-only cryptographic custody** at its core. It ingests disparate log streams, normalizes timestamps into a unified UTC chronological timeline with explicit clock uncertainty accounting, correlates events using multi-attribute link graphs, evaluates explainable anti-forensic anomalies, and generates court-grade audit reports.

---

## 2. Core Forensic Capabilities

1. **Read-Only Evidence Vault with Cryptographic SHA-256 Hashing**:
   - Computes SHA-256 hashes immediately at ingestion into separate immutable storage.
   - Preserves source byte fidelity with zero execution of uploaded files, scripts, or macros.
   - Interactive 1-click re-verification proves that files have suffered zero bit-level tampering.

2. **Deterministic Timeline Normalization Engine**:
   - Normalizes ISO8601, Unix epoch, Syslog RFC-3164/5424, Apache/Nginx, and Windows EVTX dumps into unified UTC.
   - Explicitly accounts for device clock skew (e.g. -185s DC offset) and uncertainty margins ($\pm$ seconds).
   - Clear distinction between **Observed Facts** and **Inferred Relationships**.

3. **Explainable Anomaly Detection Engine (Non-Black-Box)**:
   - Rule-based detection with MITRE ATT&CK mapping:
     - **MACB Timestomping**: $STANDARD_INFORMATION Modification timestamp earlier than Creation timestamp.
     - **Temporal Discontinuities**: Missing intervals (> 15 min gaps on active systems).
     - **Clock Drift Discrepancies**: Inter-domain desync across primary and replica DCs.
     - **Privilege Misuse**: Service account elevating to interactive root shell off-hours.
     - **Volatile Path Staging**: Execution from `/tmp` or `C:\Windows\Temp`.
   - Anti-bias requirement: Every finding provides **alternative non-malicious explanations** (e.g. logrotate rotation, NTP packet loss, archive extraction).

4. **Cross-Source Evidence Correlation Network**:
   - Links isolated events via user sessions, IP addresses, file paths/hashes, and causal sequences.
   - Visualized in an interactive SVG graph with **Confirmed**, **Probable**, and **Uncertain** link states.

5. **Official Dossier & Report Generation**:
   - Instant 1-click PDF download (via jsPDF) with custody tables, timeline listings, and forensic disclaimers.
   - Structured JSON export for cross-agency interchange.

---

## 3. UN Sustainable Development Goals (SDGs) Alignment

- **SDG 9: Industry, Innovation and Infrastructure**: Automated multi-log forensic reasoning enhances global cyber infrastructure resilience, reducing incident analysis cycle times from weeks to seconds.
- **SDG 16: Peace, Justice and Strong Institutions**: Protects the integrity of judicial and disciplinary fact-finding via cryptographic non-repudiation, transparent reasoning, and anti-bias guardrails.
- **SDG 17: Partnerships for the Goals**: Open, verifiable report standards (JSON/PDF manifests) facilitate seamless collaboration between law enforcement, academic CERTs, and incident response teams.

---

## 4. Local Execution Guide (Windows & VS Code)

### Prerequisites
- Node.js (v18+)
- Python (v3.10+)
- Visual Studio Code

### Running Full-Stack in Node/Express (Default Web App)
```bash
# Install dependencies
npm install

# Start full-stack development server on port 3000
npm run dev
```
Open your browser at `http://localhost:3000`.

### Running Python FastAPI Backend (Optional Local Service)
```powershell
# Open terminal in VS Code (PowerShell)
cd backend

# Create and activate Python virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install required Python packages
pip install -r requirements.txt

# Launch FastAPI service
python main.py
```
- FastAPI API will be active at: `http://127.0.0.1:8000`
- Interactive Swagger documentation: `http://127.0.0.1:8000/docs`

---

## 5. Built-in Synthetic Benchmark Case

Judges and evaluators can immediately evaluate the platform using the built-in synthetic benchmark:
- **Case**: *Operation Cobalt Mirage (Case #FS-2026-089)*
- **5 Multi-Source Evidence Artifacts**:
  1. `auth_syslog_bastion.log` (SSH brute force & sudo elevation)
  2. `windows_security_evtx.json` (Event 4624, 4672, and 7045 service creation)
  3. `nginx_access_cluster.log` (Webshell delivery & 32-minute log gap)
  4. `endpoint_mft_timeline.csv` (NTFS timestomping discrepancy)
  5. `radius_auth_replica.log` (185-second clock skew on secondary DC)
- Clearly labeled as **SYNTHETIC BENCHMARK** to maintain absolute forensic integrity.

---

## 6. Security & Legal Disclaimer

All findings produced by ForenSight AI are investigative hypotheses requiring qualified human examiner confirmation. Cryptographic SHA-256 digests attest to bit-level integrity from the time of ingestion; they do not attest to pre-seizure authenticity.
