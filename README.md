# Quantum Cyber Threat Detection

A team project for **KCC Build With Bharat 4.0** that demonstrates a **quantum-circuit simulation, statistical threat monitoring, and Q-Intel AI agent investigation workflow** for a simplified teleportation-based Quantum Digital Signature (QDS) session.

The application simulates normal and attack-modified sessions, compares measurement distributions with an expected reference, estimates session error rates, evaluates combined security postures, enriches investigations with technical evidence retrieved via TinyFish, and generates/emails understandable security reports to analysts.

It also ships a **live multi-device attack demo**: a WhatsApp-style group chat where optional participants play the attacker and manipulate quantum-transmitted messages in real time, watched live by the SOC dashboard.

> **Scope and limitations:** This is a research and educational prototype built with Qiskit Aer circuit simulation. It is not a production QDS deployment, a formal security proof, or a detector validated against real-world physical quantum hardware. The attack injectors represent simplified circuit-level perturbations, and thresholds are representative simulation settings that require extensive empirical benchmarking before physical hardware deployment.

---

## Team

- **Vinayak Dev Tiwari**
- **Shivansh Tiwari**
- **Ballabh Utkarsh Singh**

**Project:** Quantum Cyber Threat Detection  
**Event:** KCC Build With Bharat 4.0  
**Repository:** [github.com/vinayakdevtiwari/quantum-cyber-threat-detection](https://github.com/vinayakdevtiwari/quantum-cyber-threat-detection)

---

## What is Implemented

### 1. Quantum Simulator & Statistical Monitoring Engine
- **Quantum-session simulator (`simulator.py`)** — constructs a 3-qubit teleportation-based QDS verification circuit executed with Qiskit Aer. Features depolarizing-noise models for normal and degraded hardware environments.
- **Attack scenarios (`attacks.py`)** — circuit-level injection models for forgery ($X$ on message), impersonation ($Z$ phase-tamper), replay ($X$ on Bob's entangled qubit), channel manipulation (random Pauli $X$/$Z$), and honest baseline transmission.
- **Statistical detector (`detection.py`)** — computes a Pearson chi-squared distributional divergence against an offline calibrated 8192-shot reference distribution; derives a normalized threat score and an anomalous flag/accept verdict.
- **Security-state check (`detection.py`)** — independently monitors the teleported-bit error rate (QBER analog) against an illustrative 11% cutoff.
- **Risk engine (`risk_engine.py`)** — maps the independent security state and threat detector signals onto a 2x2 decision matrix yielding four distinct postures: `VERY STRONG`, `STRONG + ALERT`, `WEAK`, and `CRITICAL`.
- **Threshold calibration script (`calibrate.py`)** — offline Monte Carlo calibration script pooling trials across orthogonal measurement bases ($Z$ and $X$) and noise conditions.

### 2. Q-Intel AI Investigation Agent (`services/report_service.py`)
- **Session Investigation Workflow** — interprets real simulation measurements and detector outputs, formulates focused technical queries without exposing sensitive user data, and retrieves external literature using the official TinyFish API.
- **TinyFish Search & Fetch Client (`services/tinyfish_client.py`)** — reusable, resilient HTTP client targeting `https://api.search.tinyfish.ai` and `https://api.fetch.tinyfish.ai`. Features bounded timeouts, exponential backoff retries for 429/5xx, and strict non-retry on client errors.
- **TinyFish Agent Deep Research** — intentional deep research action leveraging the TinyFish Agent API (`/v1/research/async`) with structured output schemas and status polling.
- **Offline Fallback** — if TinyFish credentials are absent, Q-Intel cleanly produces an offline investigation report based strictly on simulation telemetry, explicitly labeling it as generated without live research.

### 3. Structured Investigation Report Model (`models/investigation_report.py`)
- Validated dataclass schema capturing simulation mode, basis, shot count, statistical deviation, threat score, teleportation error rate, plain-language summary, technical explanation, simulation evidence, external research findings, recommended next checks, and known limitations.
- **Strict Blind-Test Confidentiality** — in Blind test mode, ground truth attack class and channel conditions are completely withheld from the AI prompt, report state, UI preview, and email until the user explicitly triggers "Reveal Ground Truth".

### 4. Transactional Email Reporting (`services/email_service.py`)
- Integrates with the official Resend API (`POST https://api.resend.com/emails`).
- Offers two presentation styles:
  - **Simple Explanation**: tailored for non-technical leadership and operations managers.
  - **Technical Report**: comprehensive telemetry, chi-squared residuals, error rates, and hyperlinked citations.
- Dark SOC-themed responsive HTML template with strict `html.escape` sanitation against XSS injection, alongside a complete plain-text fallback alternative.
- In-UI preview, client-side recipient validation, duplicate send prevention, and server-side credential isolation.

### 5. Live Multi-Device Attack Demo (`server.py`, `rooms.py`, `room_server.py`)
- **Room-based group chat transport** — a WhatsApp-style room served by Flask, joinable from any device on the LAN with a short room code. Phones are thin clients; the laptop does all quantum work.
- **Real-time attack console (`/attack`)** — an attacker joins the same room, watches the message stream, and during the narrow transit window injects forgery, impersonation, replay, or channel manipulation per `message_layer.py`.
- **Quantum witness verification (`signature.py`)** — a physical, consumable signing state that closes the forgery and replay gap plaintext comparison cannot: forgery succeeds with probability 2**-L, and replay fails because verification measures (collapses) the witness.
- **Per-viewer privacy boundary** — private chats render only for their participants; the attack console cannot read them.
- **Forensic persistence** — every message result is written to a local SQLite database (`qds_sessions.db`, auto-created), which the Streamlit dashboard reads cross-process as its evidence trail.

---

## Architecture Overview

```text
+-----------------------------------------------------------------------------------+
|                       QDS Circuits (Qiskit Aer)                                   |
|   session simulator (simulator.py)      message layer (message_layer.py)          |
+-----------------------------------------------------------------------------------+
        |                                        |                    ^
        v                                        v                    |
+-------------------------------+   +------------------------+   +----------------------+
|   Measurement Distributions   |   |  Live Room Transport   |   |  Attack Console      |
|  (multi-qubit outcome counts) |   | rooms.py + room_server |   |  (browser/phone)     |
+-------------------------------+   +------------------------+   +----------------------+
        |                                        |                    |
        v                                        v                    |
+-------------------------------+   +------------------------+          |
|      Threat Detector          |   |   Witness Verify       |          |
|  (chi-squared divergence)     |   |   (signature.py)       |          |
+-------------------------------+   +------------------------+          |
        |                                        |                    |
        v                                        v                    |
+-------------------------------+   +---------------------------------------------+
|      Security State           |   |          Risk Engine + Metrics              |
|   (QBER <= 11%)               |   |     (2x2 matrix, attack_metrics.py)         |
+-------------------------------+   +---------------------------------------------+
        |                                        |
        +-------------------+--------------------+
                            |
                            v
                    ===============
                     Q-INTEL AGENT
                    ===============
        +-------------------------------+-------------------------------+
        v                                                               v
+-------------------------------+                               +-------------------+
|      TinyFish Research        |                               |   Report Model    |
+-------------------------------+                               +-------------------+
        |                                                               |
        v                                                               v
+-------------------------------+   +-------------------------------------------------+
|  Streamlit SOC dashboard      |   |  Forensic SQLite <- room results (phone_bridge) |
+-------------------------------+   +-------------------------------------------------+
                            |
                            v
                  Resend / SMTP email reports
```

---

## Installation & Setup

### Prerequisites
- Python 3.10+ (tested on Python 3.11)
- Git

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/vinayakdevtiwari/quantum-cyber-threat-detection.git
cd quantum-cyber-threat-detection
```

Windows PowerShell:
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

macOS / Linux:
```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy the provided template:
```bash
cp .env.example .env
```

Edit `.env` to configure your API keys (both are optional; the application includes complete offline fallbacks):

```ini
# TinyFish API Key for live research retrieval (https://agent.tinyfish.ai/api-keys)
TINYFISH_API_KEY=your_tinyfish_api_key_here

# Resend API Key for email report delivery (https://resend.com/api-keys)
RESEND_API_KEY=your_resend_api_key_here

# Verified sender address in Resend (e.g., reports@yourdomain.com)
REPORT_FROM_EMAIL=QCTD Reports <noreply@yourdomain.com>
```

> **Security Note:** `.env` and `.streamlit/secrets.toml` are strictly excluded in `.gitignore`. Never commit API keys or personal credentials.

---

## Running the Application

Launch the Streamlit SOC dashboard:

```bash
streamlit run app.py
```

The application will launch on `http://localhost:8501`.

### Running the Live Multi-Device Demo

The fastest path to the full demo — one launcher, three windows:

```bash
run_demo.bat
```

Use `run_demo.bat --check` to run preflight checks only. The launcher health-checks each service before opening the browser windows:

| Window | URL | Role |
|---|---|---|
| 1 | `http://<host-ip>:5000/room` | Victim — group chat with quantum-signed messages |
| 2 | `http://<host-ip>:5000/attack` | Attacker — manipulates messages in transit |
| 3 | `http://localhost:8501` | Streamlit SOC dashboard |

To include phones as attackers, connect them to the same Wi-Fi/LAN as the laptop and open the `/attack` URL; `network.py` prints the host address to use. Manual startup without the launcher:

```bash
python server.py                          # victim + attacker + backend on :5000
python -m streamlit run app.py --server.port 8501
```

### Operating Workflow

1. **Configure & Run Session (Tab 1: Session Overview):**
   - Select message state (`0` or `1`).
   - Select execution mode: **Manual** (specify attack injection and hardware noise) or **Blind test** (randomized ground truth).
   - Choose shot count (128 - 2048).
   - Click **RUN QDS SESSION**.
   - Review the Risk Engine alert, Teleportation Error Rate, Statistical Deviation, Threat Score, and Outcome Probabilities chart.
   - If in Blind test mode, test your assessment before clicking **REVEAL GROUND TRUTH**.

2. **Launch Q-Intel Investigation (Tab 2: AI Investigation):**
   - Click **INVESTIGATE SESSION**.
   - Q-Intel correlates the session findings, queries TinyFish Search and Fetch for relevant technical context, and formats empirical evidence.
   - Inspect the Executive Summary, Technical Telemetry, Recommended Verification Checks, and hyperlinked sources.
   - *(Optional)* Expand **Initiate Deep Research** to submit custom questions to the TinyFish Agent API.

3. **Generate and Dispatch Email Reports (Tab 3: Email Report):**
   - Choose report style: **Simple Explanation** or **Technical Report**.
   - Enter a valid recipient email address.
   - Click **REFRESH PREVIEW** to review the mobile-responsive HTML layout.
   - Click **SEND EMAIL REPORT** to dispatch the report via Resend. The interface provides confirmation with provider message IDs and guards against accidental duplicate sends.

4. **Inspect Raw Telemetry (Tab 4: Technical Evidence):**
   - Inspect the 8-bin measurement probability table, residuals, and chi-squared bin contributions.
   - Review the mathematical architecture behind the 2x2 decision matrix.

---

## Blind-Test Confidentiality Protection

To maintain rigorous experimental integrity:
- In **Blind test mode**, the application secretly selects the attack type and noise conditions.
- Before ground truth is explicitly revealed:
  - The detector verdict, error rates, and risk posture are computed purely from observed measurements.
  - The `InvestigationReport` model, Q-Intel prompts, UI panels, email previews, and outgoing emails set `actual_attack = None` and `actual_channel = None`.
  - Ground truth metadata is only integrated into reports and exports after the user explicitly presses **REVEAL GROUND TRUTH**.

---

## Running the Automated Test Suite

The repository includes a comprehensive unit and integration test suite mocking all external network requests (no API credits required):

```bash
python -m pytest tests/ -v
```

### Test Coverage Highlights:
- **`tests/test_tinyfish_client.py`**: Search/Fetch response parsing, Agent API deep research, HTTP 401/403/429/500 error handling, timeouts, malformed JSON, and missing API key guards.
- **`tests/test_investigation_report.py`**: Schema validation, plain-language and technical report synthesis, blind-test confidentiality before and after reveal, and missing data handling.
- **`tests/test_email_service.py`**: RFC email address validation, HTML escaping for XSS prevention, plain-text fallback formatting, missing configuration handling, and Resend API success/failure parsing.
- **`tests/test_report_service.py`**: End-to-end Q-Intel investigation orchestration, offline fallbacks, prevention of accidental email sends during preview, and duplicate send prevention.
- **`tests/test_signature.py`, `test_context_binding.py`, `test_message_layer.py`, `test_rooms.py`, `test_room_socket.py`**: the quantum witness layer, replay semantics, bit transport, room lifecycle, and WebSocket flow of the live demo.
- **`tests/test_attack_metrics.py`, `test_breach_console.py`**: live attack telemetry and the private-chat access gate over a real WebSocket.

---

## Project Structure

```text
quantum-cyber-threat-detection/
├── .env.example                  # Environment configuration template
├── .gitignore                    # Git exclusion rules
├── .streamlit/
│   └── config.toml               # Streamlit theme configuration
├── app.py                        # Streamlit SOC dashboard & workflow orchestration
├── attacks.py                    # Quantum attack injection models
├── attack_metrics.py             # Live attack telemetry metrics
├── calibrate.py                  # Offline threshold calibration script
├── detection.py                  # Error rate check, chi-squared deviation, threat score
├── message_layer.py              # Bit transport, verification, attack labels
├── models/
│   ├── __init__.py
│   └── investigation_report.py   # Validated investigation report domain model
├── network.py                    # LAN address discovery helper
├── phone_bridge.py               # Cross-process SQLite bridge for the dashboard
├── preflight.py                  # Demo launcher preflight checks
├── requirements.txt              # Project dependencies
├── risk_engine.py                # 2x2 security posture decision matrix
├── room_server.py                # Room HTTP + WebSocket routes
├── rooms.py                      # Room registry, membership, message lifecycle
├── run_demo.bat                  # One-command launcher for the multi-device demo
├── server.py                     # Flask backend: victim + attacker + sessions DB
├── services/
│   ├── __init__.py
│   ├── email_service.py          # Resend/SMTP transactional email client & templates
│   ├── report_service.py         # Q-Intel AI investigation agent orchestrator
│   └── tinyfish_client.py        # TinyFish Search, Fetch, and Agent API client
├── setup_email.py                # Interactive SMTP configuration helper
├── signature.py                  # Quantum witness layer (forgery/replay defense)
├── simulator.py                  # Teleportation-style QDS circuit simulation
├── static/
│   └── style.css                 # Shared styling for the Flask demo pages
├── templates/                    # Flask demo pages (room, attack, victim, attacker, index)
└── tests/                        # Unit + integration tests (12 suites, network mocked)
    ├── __init__.py
    ├── test_attack_metrics.py
    ├── test_breach_console.py
    ├── test_context_binding.py
    ├── test_email_service.py
    ├── test_investigation_report.py
    ├── test_message_layer.py
    ├── test_report_service.py
    ├── test_room_socket.py
    ├── test_rooms.py
    ├── test_signature.py
    └── test_tinyfish_client.py
```

---

## Known Limitations

1. **Simulation Model**: Execution uses Qiskit Aer depolarizing noise simulation, not physical quantum hardware (no thermal relaxation, readout crosstalk, or spatial drift).
2. **Simplified Attack Models**: Attack injectors represent discrete single-gate perturbations; real-world adversaries may deploy coherent multi-copy attacks or collective measurements.
3. **Illustrative Cutoffs**: The 11% error rate threshold is a representative BB84 QBER analog; formal QDS protocol security bounds require scheme-specific analytic proofs.
4. **Offline Calibration**: The default threshold (`0.0253`) was derived for this specific 3-qubit topology and shot count; adjustments to shot count or noise parameters require re-running `calibrate.py`.

---

## Responsible Security Use

This prototype is created for educational and research demonstrations under authorized parameters. Never commit credentials, API tokens, personal email addresses, or proprietary logs to version control.
