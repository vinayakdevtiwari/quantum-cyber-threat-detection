# Quantum Cyber Threat Detection

A team project that demonstrates a **quantum-circuit simulation and statistical monitoring workflow** for a simplified teleportation-based Quantum Digital Signature (QDS) session. The application simulates normal and attack-modified sessions, compares measurement distributions with an expected reference, estimates session error rate, and combines the signals into a readable security posture.

> **Scope and limitations:** This is a research/demo prototype built with Qiskit Aer simulation. It is not a production QDS implementation, a formal security proof, or a detector validated against real-world cyberattacks or quantum hardware. The attack injectors are simplified circuit perturbations, and the security/error thresholds are representative simulation settings that require further validation before any real deployment.

## Team

- **Vinayak Dev Tiwari**
- **Shivansh Tiwari**
- **Ballabh Utkarsh Singh**

## What is implemented

- **Quantum-session simulator (`simulator.py`)** — builds a three-qubit teleportation-style circuit and executes it with Qiskit Aer. Includes configurable depolarizing-noise models for normal and degraded simulated channel conditions.
- **Attack scenarios (`attacks.py`)** — demonstration injectors for forgery, impersonation, replay, and channel manipulation, plus an honest/no-attack case.
- **Statistical detector (`detection.py`)** — compares observed measurement counts with a cached high-shot reference distribution using a chi-squared-style deviation measure; computes a normalized threat score and a flag/accept verdict.
- **Security-state check (`detection.py`)** — estimates the teleported-bit error rate and compares it with a representative threshold.
- **Risk engine (`risk_engine.py`)** — combines the security-state result and threat verdict into a four-state posture: `VERY STRONG`, `STRONG + ALERT`, `WEAK`, or `CRITICAL`.
- **Streamlit dashboard (`app.py`)** — interactive manual and blind-test demonstrations, including the selected attack/channel scenario and the resulting metrics.
- **Threshold calibration script (`calibrate.py`)** — runs simulated trials and prints a threshold based on a target false-positive rate. Calibration is stochastic; verify the output against the current app settings before changing the configured threshold.
- **Presentation (`SIH26141_Box_Style.pptx`)** — project presentation included in the supplied project ZIP. (The presentation is not included in the GitHub upload yet.)

## Architecture

```text
QDS-style circuit simulation
        |
        +--> Measurement counts --> Statistical deviation --> Threat verdict --+
        |                                                                      |
        +--> Teleported-bit error rate --> Security state ---------------------+--> Risk posture
```

The two assessment signals are intentionally separate: a session may have an elevated error rate without the detector flagging an attack, or the detector may flag a distributional deviation. The final posture is a rule-based combination of these outputs.

## Requirements

- Python 3.10+ recommended
- Qiskit and Qiskit Aer
- NumPy, SciPy, Matplotlib, and Streamlit

Install dependencies:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

macOS/Linux:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run the application

From the project root:

```bash
streamlit run app.py
```

Streamlit will print a local URL to open in your browser. In the sidebar, choose a message state, select Manual or Blind test mode, configure the scenario, and run a session.

## Calibrate the threshold (optional)

```bash
python calibrate.py
```

The script samples honest and attacked sessions under the configured simulation conditions and prints a suggested threshold, detection rates, and false-positive rate for that run. Results can vary because the simulator and some attack scenarios are stochastic. Do not assume a target false-positive rate is guaranteed on unseen scenarios; independently validate before presenting a numeric performance claim.

`CALIBRATED_THRESHOLD` in `app.py` is a configured value. Re-run calibration and evaluate the results before changing it; do not treat the value alone as proof of measured production accuracy.

## Project files

| File | Purpose |
|---|---|
| `app.py` | Streamlit dashboard and workflow orchestration |
| `simulator.py` | Teleportation-style quantum circuit and noise models |
| `attacks.py` | Simplified circuit-level attack scenarios |
| `detection.py` | Error-rate check, distribution comparison, threshold and verdict functions |
| `risk_engine.py` | Maps the two assessment signals to a security posture |
| `calibrate.py` | Offline simulation-based threshold calibration |
| `.streamlit/config.toml` | Streamlit theme configuration |

## Important interpretation notes

- This project uses a **quantum circuit simulator**, not physical quantum hardware.
- The simulated attack labels are illustrative circuit modifications; they are not a complete model of real adversaries.
- The chi-squared-style distance implemented here is a custom distribution-deviation score. It should not be described as a formal hypothesis test without further statistical validation.
- The security-state cutoff is representative and is **not derived as a security bound for this exact protocol**.
- Calibration output is simulation-specific and stochastic. Report measured results only with the trial count, configuration, and evaluation method stated.
- A `VERY STRONG` posture means only that these prototype checks passed for that simulated session; it is not a guarantee of real-world security.

## Current status

This repository documents the supplied prototype and its current simulation workflow. Broader QDS security proofs, formal protocol validation, robust benchmarking, and testing against realistic adversarial models remain future work.

## Security and responsible use

Use only authorized, synthetic, or otherwise permitted data. Never commit credentials, API keys, personal data, or sensitive logs.
