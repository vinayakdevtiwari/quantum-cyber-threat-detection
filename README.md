# Quantum Cyber Threat Detection

A team project for **KCC Build With Bharat 4.0** that demonstrates a **quantum-circuit simulation, statistical threat monitoring, and Q-Intel AI agent investigation workflow** for a simplified teleportation-based Quantum Digital Signature (QDS) session.

The application simulates normal and attack-modified sessions, compares measurement distributions with an expected reference, estimates session error rates, evaluates combined security postures, enriches investigations with technical evidence retrieved via TinyFish, and generates/emails understandable security reports to analysts.

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

---

## Architecture Overview

```text
+-----------------------------------------------------------------------------------+
|                           QDS Circuit Simulation (Qiskit Aer)                     |
+-----------------------------------------------------------------------------------+
        |                                                                 |
        v                                                                 v
+-------------------------------+                                 +-----------------+
|   Measurement Distributions   |                                 |   Bit Fidelity  |
| (Multi-qubit outcome counts)  |                                 |  (clbit 2 error)|
+-------------------------------+                                 +-----------------+
        |                                                                 |
        v                                                                 v
+-------------------------------+                                 +-----------------+
|      Threat Detector          |                                 | Security State  |
| (Chi-squared divergence test) |                                 |  (QBER <= 11%)  |
+-------------------------------+                                 +-----------------+
        |                                                                 |
        +-------------------------------+---------------------------------+
                                        |
                                        v
                        +-------------------------------+
                        |          Risk Engine          |
                        |      (2x2 Decision Matrix)    |
                        +-------------------------------+
                                        |
                                        v
                    =========================================
                               Q-INTEL AGENT CORE
                    =========================================
                                        |
        +-------------------------------+-------------------------------+
        |                                                               |
        v                                                               v
+-------------------------------+                               +-------------------+
|      TinyFish Research        |                               |   Report Model    |
| - Search API                  |                               | - Plain Summary   |
| - Fetch API                   |                               | - Tech Telemetry  |
| - Agent Deep Research         |                               | - Recommendations |
+-------------------------------+                               +-------------------+
        |                                                               |
        +-------------------------------+-------------------------------+
                                        |
                                        v
                        +-------------------------------+
                        |       Report Distribution     |
                        | - Streamlit SOC Interface     |
                        | - Resend Transactional Email  |
                        +-------------------------------+
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
├── calibrate.py                  # Offline threshold calibration script
├── detection.py                  # Error rate check, chi-squared deviation, threat score
├── models/
│   ├── __init__.py
│   └── investigation_report.py   # Validated investigation report domain model
├── requirements.txt              # Project dependencies
├── risk_engine.py                # 2x2 security posture decision matrix
├── services/
│   ├── __init__.py
│   ├── email_service.py          # Resend transactional email client & templates
│   ├── report_service.py         # Q-Intel AI investigation agent orchestrator
│   └── tinyfish_client.py        # TinyFish Search, Fetch, and Agent API client
├── simulator.py                  # Teleportation-style QDS circuit simulation
└── tests/
    ├── __init__.py
    ├── test_email_service.py
    ├── test_investigation_report.py
    ├── test_report_service.py
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
