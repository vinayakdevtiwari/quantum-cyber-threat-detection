# Quantum Cyber Threat Detection

An educational prototype exploring cyber-threat scenarios with simulated quantum-inspired components and risk scoring.

## Team
- Vinayak Dev Tiwari
- Shivansh Tiwari
- Ballabh Utkarsh Singh

## Project status
This repository contains a prototype for exploration and demonstration. It should not be treated as a production security product. Quantum-inspired simulations, scenario data, and heuristic risk scoring do not by themselves establish real-world detection accuracy. Validate each component before making performance claims.

## Getting started

### Requirements
- Python 3.10 or newer (recommended)
- pip

### Install

```bash
python -m venv .venv
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Run

```bash
streamlit run app.py
```

## Main files
- `app.py` — Streamlit application interface.
- `attacks.py` — attack/scenario definitions.
- `detection.py` — detection logic.
- `risk_engine.py` — risk scoring logic.
- `simulator.py` — simulation components.
- `calibrate.py` — calibration utilities.

## Limitations
This is a prototype. Do not rely on its scores for real security decisions, and do not infer real quantum advantage or production-grade threat detection without reproducible evaluation against labeled datasets and suitable baselines.

## Security
Use only authorized, synthetic, or otherwise permitted data. Never commit credentials, API keys, personal data, or sensitive logs.
