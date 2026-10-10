"""
app.py

Streamlit application for the Quantum Cyber Threat Detection framework.
Includes:
- Interactive QDS session simulator with hardware noise and attack injection
- Statistical Threat Detector + Teleportation Error Rate Security State + 2x2 Risk Engine
- Q-Intel AI Investigation Agent powered by TinyFish Search, Fetch, and Deep Research
- Structured report generator with blind-test protection
- Transactional email reporting powered by Resend with live preview and send controls
"""

import os
import random
from datetime import datetime, timezone
import streamlit as st
from typing import Optional, List, Dict, Any

# Load environment variables from .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from simulator import (
    run_session, stable_expected_distribution,
    DEFAULT_NOISE_MODEL, DEGRADED_NOISE_MODEL,
)
from attacks import ATTACKS
from detection import (
    chi_squared_deviation, threat_score, verdict,
    teleportation_error_rate, security_state, SECURITY_ERROR_THRESHOLD,
)
from risk_engine import compute_posture, posture_explanation
from models.investigation_report import InvestigationReport
from phone_bridge import get_phone_report_data, list_recent_sessions, db_written_since, db_timestamp
from attack_metrics import compute_attack_metrics, explain
from message_layer import ATTACK_LABELS, MAX_MESSAGE_CHARS
import requests

# The phone-demo backend that owns the session database. The Live Attack tab
# calls it to inject attacks; kept in one place so a port change is a one-line
# edit rather than a hunt through the view.
BACKEND_URL = os.environ.get("QDS_BACKEND_URL", "http://localhost:5000")
from services.report_service import QIntelAgent
from services.email_service import validate_email, parse_recipients

# Calibrated threshold offline via calibrate.py with pooled bases (Z and X)
CALIBRATED_THRESHOLD = 0.0253

ATTACK_LABELS = {
    "none": "None (honest channel)",
    "forgery": "Forgery",
    "impersonation": "Impersonation",
    "replay": "Replay",
    "channel_manipulation": "Channel manipulation",
}

POSTURE_STYLE = {
    "VERY STRONG": ("ok", "OK"),
    "STRONG + ALERT": ("warn", "!"),
    "WEAK": ("warn", "!"),
    "CRITICAL": ("bad", "X"),
}

PIPELINE = (
    "key setup -> entanglement -> teleportation -> Pauli correction/verification "
    "-> [Security State: error-rate check] + [Threat Detector: statistical deviation test] "
    "-> Risk Engine -> combined security posture. Threshold calibrated offline via calibrate.py."
)

SOC_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Share+Tech+Mono&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

html, body, [data-testid="stAppViewContainer"], .stApp {
    background-color: #0e1117 !important;
    color: #c9d1d9;
}

[data-testid="stHeader"] {
    background: rgba(14, 17, 23, 0.85) !important;
    border-bottom: 1px solid rgba(0, 255, 136, 0.18);
}

[data-testid="stToolbar"] { background: transparent !important; }

.block-container {
    padding-top: 1.2rem;
    padding-bottom: 2.5rem;
    max-width: 1400px;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0b0e14 0%, #12161e 100%) !important;
    border-right: 1px solid rgba(0, 255, 136, 0.16);
}

[data-testid="stSidebar"] * {
    font-family: "IBM Plex Sans", sans-serif;
}

h1, h2, h3, .soc-brand {
    font-family: "Orbitron", sans-serif !important;
    letter-spacing: 0.08em;
}

code, pre, .mono {
    font-family: "Share Tech Mono", monospace !important;
}

.soc-topbar {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 1rem;
    flex-wrap: wrap;
    border: 1px solid rgba(0, 255, 136, 0.22);
    background:
        linear-gradient(135deg, rgba(0, 255, 136, 0.06), rgba(14, 17, 23, 0.9) 42%),
        repeating-linear-gradient(90deg, rgba(0, 255, 136, 0.04) 0 1px, transparent 1px 18px);
    padding: 1.15rem 1.35rem 1.05rem;
    margin-bottom: 1.15rem;
    box-shadow: 0 0 24px rgba(0, 255, 136, 0.08);
}

.soc-kicker {
    font-family: "Share Tech Mono", monospace;
    color: #00ff88;
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.22em;
    margin: 0 0 0.35rem 0;
}

.soc-title {
    font-family: "Orbitron", sans-serif;
    font-size: 1.55rem;
    margin: 0;
    color: #f0f6fc;
    text-shadow: 0 0 18px rgba(0, 255, 136, 0.25);
}

.soc-sub {
    margin: 0.35rem 0 0 0;
    color: #8b949e;
    font-size: 0.92rem;
}

.soc-meta {
    text-align: right;
    font-family: "Share Tech Mono", monospace;
    color: #7ee787;
    font-size: 0.8rem;
}

.soc-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #00ff88;
    box-shadow: 0 0 10px #00ff88;
    margin-right: 8px;
    animation: pulse 1.8s ease-in-out infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.35; }
}

.alert-ok, .alert-bad, .alert-warn {
    border-radius: 8px;
    padding: 1rem 1.2rem;
    margin: 0.35rem 0 1.1rem 0;
    font-family: "IBM Plex Sans", sans-serif;
    display: flex;
    gap: 0.9rem;
    align-items: flex-start;
}

.alert-ok {
    background: rgba(0, 255, 136, 0.08);
    border: 1px solid #00ff88;
    box-shadow: 0 0 22px rgba(0, 255, 136, 0.18);
    color: #b6ffd7;
}

.alert-bad {
    background: rgba(255, 45, 85, 0.1);
    border: 1px solid #ff2d55;
    box-shadow: 0 0 26px rgba(255, 45, 85, 0.22);
    color: #ffd0d9;
}

.alert-warn {
    background: rgba(255, 196, 0, 0.08);
    border: 1px solid #ffc400;
    box-shadow: 0 0 22px rgba(255, 196, 0, 0.18);
    color: #ffe9a8;
}

.alert-icon {
    font-size: 1.45rem;
    line-height: 1;
    margin-top: 0.05rem;
}

.alert-title {
    font-family: "Orbitron", sans-serif;
    font-size: 0.95rem;
    letter-spacing: 0.12em;
    margin: 0 0 0.2rem 0;
}

.alert-body { margin: 0; font-size: 0.95rem; opacity: 0.92; }

.metric-card {
    border: 1px solid rgba(0, 255, 136, 0.2);
    background: linear-gradient(180deg, #141922 0%, #10141b 100%);
    padding: 1rem 1.05rem 0.95rem;
    min-height: 132px;
    box-shadow: inset 0 1px 0 rgba(0, 255, 136, 0.08), 0 10px 24px rgba(0, 0, 0, 0.35);
}

.metric-card.danger {
    border-color: rgba(255, 45, 85, 0.45);
    box-shadow: inset 0 1px 0 rgba(255, 45, 85, 0.12), 0 10px 24px rgba(0, 0, 0, 0.35);
}

.metric-card.warn {
    border-color: rgba(255, 196, 0, 0.45);
    box-shadow: inset 0 1px 0 rgba(255, 196, 0, 0.12), 0 10px 24px rgba(0, 0, 0, 0.35);
}

.metric-label {
    font-family: "Share Tech Mono", monospace;
    font-size: 0.72rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: #8b949e;
    margin-bottom: 0.45rem;
}

.metric-value {
    font-family: "Orbitron", sans-serif;
    font-size: 1.7rem;
    color: #00ff88;
    text-shadow: 0 0 12px rgba(0, 255, 136, 0.35);
}

.metric-card.danger .metric-value {
    color: #ff4d6d;
    text-shadow: 0 0 12px rgba(255, 45, 85, 0.4);
}

.metric-card.warn .metric-value {
    color: #ffc400;
    text-shadow: 0 0 12px rgba(255, 196, 0, 0.4);
}

.metric-hint {
    margin-top: 0.4rem;
    font-size: 0.78rem;
    color: #7d8590;
    font-family: "Share Tech Mono", monospace;
}

.idle-panel {
    border: 1px dashed rgba(0, 255, 136, 0.25);
    padding: 1.6rem 1.2rem;
    color: #8b949e;
    background: rgba(22, 27, 34, 0.45);
    text-align: center;
    font-family: "Share Tech Mono", monospace;
    margin: 1.5rem 0;
}

.pipeline {
    margin-top: 1.6rem;
    padding: 0.85rem 1rem;
    border-top: 1px solid rgba(0, 255, 136, 0.16);
    color: #6e7681;
    font-size: 0.82rem;
    font-family: "Share Tech Mono", monospace;
}

div[data-testid="stExpander"] {
    background: #12161e;
    border: 1px solid rgba(0, 255, 136, 0.16) !important;
}

.stButton > button {
    width: 100%;
    background: linear-gradient(90deg, #063 0%, #00c46a 55%, #00ff88 100%) !important;
    color: #04110a !important;
    border: 0 !important;
    font-family: "Orbitron", sans-serif !important;
    letter-spacing: 0.12em;
    font-weight: 700 !important;
    box-shadow: 0 0 18px rgba(0, 255, 136, 0.35);
}

.stButton > button:hover {
    filter: brightness(1.08);
}

.intel-panel {
    border: 1px solid rgba(0, 255, 136, 0.22);
    background: linear-gradient(180deg, #121720 0%, #0c1017 100%);
    padding: 1.3rem 1.4rem;
    border-radius: 8px;
    margin-bottom: 1.2rem;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
}

.intel-panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid rgba(0, 255, 136, 0.16);
    padding-bottom: 0.7rem;
    margin-bottom: 1rem;
}

.intel-title {
    font-family: "Orbitron", sans-serif;
    color: #00ff88;
    font-size: 1.15rem;
    margin: 0;
    letter-spacing: 0.08em;
}

.pill-status {
    font-family: "Share Tech Mono", monospace;
    font-size: 0.72rem;
    padding: 3px 9px;
    border-radius: 4px;
    letter-spacing: 0.1em;
    font-weight: 700;
}

.pill-active {
    background: rgba(0, 255, 136, 0.15);
    border: 1px solid #00ff88;
    color: #00ff88;
}

.pill-offline {
    background: rgba(255, 196, 0, 0.15);
    border: 1px solid #ffc400;
    color: #ffc400;
}

.pill-error {
    background: rgba(255, 45, 85, 0.15);
    border: 1px solid #ff2d55;
    color: #ff4d6d;
}

/* Tabs customization */
button[data-baseweb="tab"] {
    font-family: "Orbitron", sans-serif !important;
    letter-spacing: 0.06em;
    font-size: 0.85rem !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #00ff88 !important;
    border-bottom: 2px solid #00ff88 !important;
}
</style>
"""


def _bitstrings(num_bits: int = 3):
    return [format(i, f"0{num_bits}b") for i in range(2 ** num_bits)]


def counts_to_probs(counts: dict, num_bits: int = 3):
    total = max(sum(counts.values()), 1)
    keys = _bitstrings(num_bits)
    return {k: counts.get(k, 0) / total for k in keys}


def render_posture_alert(posture: str, explanation: str, threat_label: str, sec_state: str):
    style, icon = POSTURE_STYLE.get(posture, ("warn", "!"))
    css_class = {"ok": "alert-ok", "warn": "alert-warn", "bad": "alert-bad"}[style]
    st.markdown(
        f"""
        <div class="{css_class}" role="alert">
          <div class="alert-icon">{icon}</div>
          <div>
            <p class="alert-title">RISK ENGINE VERDICT -- {posture}</p>
            <p class="alert-body">
              Security State: <b>{sec_state}</b> &middot; Threat Detector: <b>{threat_label.replace('_', ' ')}</b>.
              {explanation}
            </p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_metric_card(label: str, value: str, hint: str, danger: bool = False, warn: bool = False):
    klass = "metric-card"
    if danger:
        klass += " danger"
    elif warn:
        klass += " warn"
    st.markdown(
        f"""
        <div class="{klass}">
          <div class="metric-label">{label}</div>
          <div class="metric-value">{value}</div>
          <div class="metric-hint">{hint}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# Streamlit Page Setup
st.set_page_config(
    page_title="Quantum Cyber Threat Detection",
    page_icon=":satellite:",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(SOC_CSS, unsafe_allow_html=True)

# Topbar
now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
st.markdown(
    f"""
    <div class="soc-topbar">
      <div>
        <p class="soc-kicker">Quantum Cyber Threat Detection &middot; Team Project</p>
        <h1 class="soc-title">QUANTUM CYBER THREAT DETECTION</h1>
        <p class="soc-sub">QDS Security Monitoring &amp; Q-Intel Investigation Agent &middot; Team: Vinayak Dev Tiwari, Shivansh Tiwari, Ballabh Utkarsh Singh</p>
      </div>
      <div class="soc-meta">
        <div><span class="soc-dot"></span>SIMULATION NODE QDS-ALPHA</div>
        <div>TIME: {now_utc}</div>
        <div>AGENT: Q-INTEL ACTIVE</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Instantiate Agent Service
agent = QIntelAgent()

# Initialize session state tracking
if "last_run" not in st.session_state:
    st.session_state["last_run"] = None
if "investigation_report" not in st.session_state:
    st.session_state["investigation_report"] = None
if "email_dispatches" not in st.session_state:
    st.session_state["email_dispatches"] = {}

# Sidebar Configuration
with st.sidebar:
    st.markdown("### Mission parameters")
    st.caption("Configure the QDS session, then execute a live statistical check.")

    message_state = st.selectbox(
        "Message state to sign/teleport",
        ["0", "1"],
        index=1,
        help="Basis state encoded on the message qubit.",
    )

    demo_mode = st.radio(
        "Mode",
        ["Manual", "Blind test"],
        index=0,
        help="Manual: configure scenario directly. Blind test: secretly randomizes scenario -- test detection before revealing ground truth.",
    )

    if demo_mode == "Manual":
        attack_keys = list(ATTACKS.keys())
        attack_choice = st.selectbox(
            "Simulate attack type",
            attack_keys,
            index=0,
            format_func=lambda k: ATTACK_LABELS.get(k, k),
            help="Injected after entanglement, before Bell measurement.",
        )
        channel_choice = st.selectbox(
            "Background hardware noise",
            ["Normal", "Degraded"],
            index=0,
            help="Controls baseline depolarizing noise on hardware.",
        )
    else:
        st.info("Attack class and channel condition will be chosen secretly.")
        attack_choice = None
        channel_choice = None

    shots = st.slider("Shots per session", 128, 2048, 512, step=128)

    st.markdown("---")
    run_clicked = st.button("RUN QDS SESSION", type="primary")
    st.caption("Honest baseline uses a cached 8192-shot reference distribution.")

    st.markdown("---")
    st.markdown("### Service Telemetry")
    tf_status = "ONLINE" if agent.research_available else "OFFLINE"
    tf_class = "pill-active" if agent.research_available else "pill-offline"
    em_status = "ONLINE" if agent.email_available else "OFFLINE"
    em_class = "pill-active" if agent.email_available else "pill-offline"

    st.markdown(
        f"""
        <div style="font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; line-height: 1.8;">
          <div>TinyFish Research: <span class="pill-status {tf_class}">{tf_status}</span></div>
          <div>Resend Email API: <span class="pill-status {em_class}">{em_status}</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if not agent.research_available or not agent.email_available:
        st.caption("Configure TINYFISH_API_KEY and RESEND_API_KEY in .env or secrets to activate live external tools.")

# Run Session Logic
if run_clicked:
    if demo_mode == "Blind test":
        actual_attack = random.choice(list(ATTACKS.keys()))
        actual_channel = random.choice(["Normal", "Degraded"])
    else:
        actual_attack = attack_choice
        actual_channel = channel_choice

    noise_model = DEGRADED_NOISE_MODEL if actual_channel == "Degraded" else DEFAULT_NOISE_MODEL
    session_basis = random.choice(["Z", "X"])

    with st.spinner("Running quantum session simulation..."):
        expected = stable_expected_distribution(message_state, noise_model=noise_model, basis=session_basis)
        observed = run_session(message_state, attack_fn=ATTACKS[actual_attack], shots=shots,
                                noise_model=noise_model, basis=session_basis)

        # Threat Detector
        deviation = chi_squared_deviation(observed, expected)
        score = threat_score(deviation, CALIBRATED_THRESHOLD)
        result = verdict(score)
        threat_label = "THREAT" if "ANOMALOUS" in result else "NO_THREAT"

        # Security State
        error_rate = teleportation_error_rate(observed, message_state)
        sec_state = security_state(error_rate)

        # Risk Engine
        posture = compute_posture(sec_state, threat_label)
        explanation = posture_explanation(posture)

    st.session_state["last_run"] = {
        "message_state": message_state,
        "actual_attack": actual_attack,
        "actual_channel": actual_channel,
        "session_basis": session_basis,
        "blind": demo_mode == "Blind test",
        "shots": shots,
        "expected": expected,
        "observed": observed,
        "deviation": deviation,
        "score": score,
        "result": result,
        "threat_label": threat_label,
        "error_rate": error_rate,
        "sec_state": sec_state,
        "posture": posture,
        "explanation": explanation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "revealed": False,
    }
    # Reset old report and dispatches when new session runs
    st.session_state["investigation_report"] = None

last = st.session_state.get("last_run")

# Render Main Layout
tab_overview, tab_attack, tab_investigation, tab_email, tab_evidence = st.tabs([
    "1. Session Overview",
    "2. Live Attack",
    "3. AI Investigation (Q-Intel)",
    "4. Email Report",
    "5. Technical Evidence",
])

# ==============================================================================
# TAB 1: SESSION OVERVIEW
# ==============================================================================
with tab_overview:
    if last is None:
        st.markdown(
            '<div class="idle-panel">AWAITING SESSION &middot; CONFIGURE PARAMETERS IN SIDEBAR AND CLICK RUN QDS SESSION</div>',
            unsafe_allow_html=True,
        )
    else:
        render_posture_alert(last["posture"], last["explanation"], last["threat_label"], last["sec_state"])

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            render_metric_card(
                "Teleportation Error Rate",
                f"{last['error_rate']*100:.1f}%",
                f"Security threshold {SECURITY_ERROR_THRESHOLD*100:.0f}%",
                danger=(last["sec_state"] == "INSECURE"),
            )
        with c2:
            render_metric_card(
                "Statistical Deviation",
                f"{last['deviation']:.4f}",
                "chi-sq distance vs honest baseline",
                danger=(last["threat_label"] == "THREAT"),
            )
        with c3:
            delta = last["score"] - 1.0
            display_score = min(last["score"], 10.0)
            score_suffix = "+" if last["score"] > 10.0 else ""
            render_metric_card(
                "Threat Score",
                f"{display_score:.2f}{score_suffix}",
                f"score >= 1.0 flags, delta to gate {delta:+.2f}",
                danger=(last["threat_label"] == "THREAT"),
            )
        with c4:
            render_metric_card(
                "Security Posture",
                last["posture"],
                "Risk Engine combined verdict",
                danger=(last["posture"] == "CRITICAL"),
                warn=(last["posture"] in ("WEAK", "STRONG + ALERT")),
            )

        if last["blind"]:
            st.markdown("")
            if not last["revealed"]:
                col_btn, _ = st.columns([1, 3])
                with col_btn:
                    if st.button("REVEAL GROUND TRUTH"):
                        st.session_state["last_run"]["revealed"] = True
                        if st.session_state.get("investigation_report"):
                            # Update existing report after explicit reveal
                            rep = st.session_state["investigation_report"]
                            rep.ground_truth_revealed = True
                            rep.actual_attack = last["actual_attack"]
                            rep.actual_channel = last["actual_channel"]
                        st.rerun()
            else:
                st.markdown(
                    f"**Actual attack:** {ATTACK_LABELS.get(last['actual_attack'], last['actual_attack'])}  \n"
                    f"**Actual channel:** {last['actual_channel']}"
                )
                correct_threat = (last["actual_attack"] != "none") == (last["threat_label"] == "THREAT")
                st.caption(
                    f"Threat Detector called it {'correctly' if correct_threat else 'incorrectly'}. "
                    "Security State reflects combined noise + attack effects on error rate."
                )

        st.markdown("")
        left, right = st.columns((1.15, 1))
        with left:
            st.markdown("#### Outcome probabilities")
            expected_p = counts_to_probs(last["expected"])
            observed_p = counts_to_probs(last["observed"])
            keys = _bitstrings()
            rows = {
                "expected": [expected_p[k] for k in keys],
                "observed": [observed_p[k] for k in keys],
            }
            st.bar_chart(rows, color=["#00ff88", "#ff2d55"], x_label="bitstring index (000...111)")
            st.caption("Green = expected honest baseline, Red = observed session")

        with right:
            st.markdown("#### Session metadata")
            meta = {
                "message_state": last["message_state"],
                "measurement_basis": last["session_basis"],
                "shots": last["shots"],
                "threat_verdict": last["result"],
                "security_state": last["sec_state"],
                "posture": last["posture"],
                "completed_utc": last["timestamp"],
            }
            if not last["blind"] or last["revealed"]:
                meta["attack"] = ATTACK_LABELS.get(last["actual_attack"], last["actual_attack"])
                meta["channel"] = last["actual_channel"]
            st.write(meta)

        with st.expander("Raw measurement counts"):
            st.write("Expected (honest baseline):", last["expected"])
            st.write("Observed (this session):", last["observed"])
            st.caption("Counts are Qiskit bitstrings (leftmost character = clbit 2, the teleported/verified qubit).")

        st.markdown(f'<div class="pipeline">Pipeline: {PIPELINE}</div>', unsafe_allow_html=True)

def render_report_body(report: Optional[InvestigationReport]) -> None:
    """
    Render a loaded investigation report.

    Extracted from the Tab 2 body so it can be called for EITHER source. It
    previously lived inside the `if last is None: ... else: ...` block, which
    meant a phone-demo incident built a valid report that was never shown --
    the user saw "Session overview loaded" and then nothing at all.

    Keeping it as its own function also means Tab 3 can reuse it if needed
    without duplicating the markup.
    """
    if report is None:
        return

    status_color = "pill-active" if report.research_status == "completed" else "pill-offline"
    if report.research_status == "error":
        status_color = "pill-error"

    st.markdown(
        f"""
        <div class="intel-panel">
          <div class="intel-panel-header">
            <span class="intel-title">Q-INTEL CASE FILE #{report.report_id[:8].upper()}</span>
            <span class="pill-status {status_color}">RESEARCH STATUS: {report.research_status.upper()}</span>
          </div>
          <div style="font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; color: #8b949e; margin-bottom: 0.8rem;">
            TIMESTAMP: {report.timestamp_utc} &middot; MODE: {report.simulation_mode.upper()} &middot; VERDICT: {report.detector_verdict}
          </div>
          <p style="font-size: 0.95rem; line-height: 1.6; color: #d0d7de; margin-bottom: 0.5rem;">
            {report.plain_summary}
          </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Phone incidents carry their own headline: what was tampered with. Show it
    # at the top rather than leaving it buried in the evidence list.
    phone = st.session_state.get("phone_session")
    if phone:
        st.markdown("#### Attack Overview")
        h1, h2 = st.columns(2)
        with h1:
            st.markdown(f"**Signed:** `{phone['original_message']}`")
        with h2:
            st.markdown(f"**Received:** `{phone['received_message']}`")
        st.caption(
            f"Session {phone['session_code']} · attack {phone['attack_type'] or 'none'} · "
            f"{phone['corrupted_bits']}/{phone['total_bits']} bits corrupted · "
            f"posture {phone['posture']}"
        )
        witness = phone.get("witness") or {}
        if witness.get("verdict"):
            st.caption(f"Quantum witness: {witness['verdict']}")
        if witness.get("context_verdict"):
            st.caption(f"Context binding: {witness['context_verdict']}")

    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("#### Technical Interpretation")
        st.markdown(f"> {report.technical_explanation}")

        st.markdown("#### Empirical Session Evidence")
        for ev in report.simulation_evidence:
            st.markdown(f"- `{ev}`")

        st.markdown("#### Recommended Verification Checks")
        for rec in report.recommended_checks:
            st.markdown(f"- [ ] {rec}")

    with col_right:
        st.markdown("#### External Research Findings (TinyFish)")
        if report.external_research:
            for item in report.external_research:
                st.markdown(f"- {item}")
        else:
            if report.research_status == "not_configured":
                st.info("Live external research unavailable (TINYFISH_API_KEY is not configured). Falling back to offline report mode.")
            elif report.research_status == "unavailable":
                st.warning("No relevant external literature findings returned for the formulated query.")
            else:
                st.write("No external findings recorded.")

        if report.source_links:
            st.markdown("#### Cited Technical Sources")
            for s in report.source_links:
                st.markdown(f"- [{s.title}]({s.url})")

        st.markdown("#### Limitations & Scoping")
        for lim in report.known_limitations:
            st.markdown(f"- *{lim}*")

    st.markdown("---")
    with st.expander("Initiate Deep Research (TinyFish Agent API)"):
        st.caption(
            "Deep Research executes multi-iteration autonomous web research. "
            "Note: This action calls the TinyFish Agent API and may consume account credits."
        )
        custom_q = st.text_input(
            "Explicit Technical Research Question",
            value="What are established statistical thresholding criteria for detecting eavesdropping in teleportation QDS with basis mismatch?",
            help="Narrow, technical question regarding the simulated scenario.",
        )
        deep_clicked = st.button("EXECUTE DEEP RESEARCH", key="deep_research_btn")
        if deep_clicked:
            if not agent.research_available:
                st.error("Deep research requires a valid TINYFISH_API_KEY server-side.")
            else:
                with st.spinner("TinyFish Agent executing deep research iterations..."):
                    agent.run_deep_research(report, custom_q)
                    st.session_state["investigation_report"] = report
                    st.rerun()


# ==============================================================================
# TAB 2: LIVE ATTACK
# ==============================================================================
# Runs attacks from the dashboard itself and renders the same four SOC metric
# cards the single-qubit view uses. The second phone remains useful for the
# two-device story, but this makes every attack reachable in one click, which
# matters because a hotspot can fail mid-demo.
with tab_attack:
    st.markdown("### Live Attack Console")
    st.caption(
        "Inject a quantum-channel attack and read the result as SOC telemetry. "
        "Same simulation and same detection as the phone demo -- this just "
        "removes the second device from the critical path."
    )

    ac1, ac2, ac3 = st.columns([1.3, 1.3, 1])
    with ac1:
        atk_message = st.text_input("Message", value="TRANSFER $5000",
                                    max_chars=MAX_MESSAGE_CHARS)
    with ac2:
        atk_choice = st.selectbox("Attack type", list(ATTACK_LABELS.keys()),
                                  index=0,
                                  format_func=lambda k: ATTACK_LABELS[k])
    with ac3:
        atk_shots = st.slider("Shots per bit", 64, 256, 96, step=32)

    payload = {"message": atk_message, "attack": atk_choice, "shots": atk_shots}

    if atk_choice == "forgery":
        atk_bits = st.text_input("Bit indices to flip", value="40,41,42,43")
        payload["target_bits"] = atk_bits
    if atk_choice in ("forgery_substitute", "replay"):
        atk_repl = st.text_input("Replacement message", value="ATTACKER WAS HERE")
        payload["substitute"] = atk_repl

    if st.button("INJECT ATTACK", type="primary", key="run_attack_btn"):
        try:
            with st.spinner("Running quantum session and injecting attack..."):
                resp = requests.post(f"{BACKEND_URL}/api/run_attack",
                                     json=payload, timeout=300)
                data = resp.json()
            if not data.get("ok"):
                st.error(data.get("error", "Attack failed."))
            else:
                st.session_state["attack_code"] = data["code"]
                st.session_state["attack_done"] = True
                st.success(
                    f"Attack injected on session {data['code']}: "
                    f"{data['corrupted_count']}/{data['total_bits']} bits corrupted."
                )
        except Exception as e:
            st.error(f"Could not reach the phone backend ({BACKEND_URL}): {e}. "
                     f"Start it with run_demo.bat.")

    # --- Live telemetry ----------------------------------------------------
    # Prefers an attack just run here, else the most recent phone incident, so
    # the tab shows something useful without extra clicks either way.
    live_code = st.session_state.get("attack_code")
    if not live_code:
        recent_live = list_recent_sessions(1)
        live_code = recent_live[0]["code"] if recent_live else None

    live = get_phone_report_data(live_code) if live_code else None

    if not live:
        st.info(
            "No attack to show yet. Inject one above, or run the phone demo, "
            "and the telemetry appears here automatically."
        )
    else:
        m = compute_attack_metrics(live)

        mc1, mc2, mc3, mc4 = st.columns(4)
        with mc1:
            render_metric_card(
                "Bit Integrity Error Rate",
                f"{m['error_rate']*100:.1f}%",
                f"Security threshold {m['error_threshold']*100:.0f}%",
                danger=(m["security_state"] == "INSECURE"),
            )
        with mc2:
            render_metric_card(
                "Statistical Deviation",
                f"{m['deviation']:.2f}",
                "chi-sq, bit-match vs honest baseline",
                danger=(m["threat_label"] == "THREAT"),
            )
        with mc3:
            render_metric_card(
                "Threat Score",
                f"{m['threat_score']:.2f}",
                f"score >= 1.0 flags, delta to gate {m['threat_score']-1.0:+.2f}",
                danger=(m["threat_label"] == "THREAT"),
            )
        with mc4:
            render_metric_card(
                "Security Posture",
                m["posture"],
                "Risk Engine combined verdict",
                danger=(m["posture"] == "CRITICAL"),
                warn=(m["posture"] in ("WEAK", "STRONG + ALERT")),
            )

        st.markdown("#### Session")
        sc1, sc2 = st.columns(2)
        with sc1:
            st.markdown(f"**Signed:** `{live['original_message']}`")
        with sc2:
            st.markdown(f"**Received:** `{live['received_message']}`")

        st.caption(explain(m, live))
        if live.get("attack_description"):
            st.caption(live["attack_description"])
        if m.get("signature_verdict"):
            st.caption(
                f"Quantum witness: {m['signature_verdict']} · "
                f"context binding: {m.get('context_verdict') or 'n/a'}"
            )

        if live.get("corrupted_indices"):
            shown = ", ".join(str(b) for b in live["corrupted_indices"][:14])
            more = len(live["corrupted_indices"]) - 14
            st.caption(
                f"Corrupted bit indices: {shown}"
                + (f" ... (+{more} more)" if more > 0 else "")
            )

        st.markdown("---")
        st.caption(
            "Hand this session to the AI Investigation tab to attach TinyFish "
            "research and email the report."
        )

# ==============================================================================
# TAB 3: AI INVESTIGATION (Q-INTEL)
# ==============================================================================
with tab_investigation:
    st.markdown("### Q-Intel AI Investigation Agent")
    st.caption(
        "Interprets real session measurements, queries TinyFish research endpoints for technical context, "
        "and synthesizes a verified, structured investigation report."
    )

    # ------------------------------------------------------------------
    # Import an incident captured by the two-device phone demo
    #
    # Deliberately NOT hidden in a collapsed expander. Phone attacks are the
    # live half of the demo, and burying the import under a closed panel meant
    # the dashboard looked empty even while attacks were landing. The "latest
    # attack" strip makes it obvious at a glance that something happened on the
    # other device.
    # ------------------------------------------------------------------
    # Pick up attacks that land while the dashboard is open. Streamlit only
    # re-reads on an explicit interaction, so a phone attack would otherwise
    # not appear until the user touched something else -- which made this
    # panel look static during a live demo.
    #
    # st.fragment(run_every=...) re-executes ONLY this block on a timer,
    # without rerunning the whole app. That matters here: a full rerun would
    # reset session state and defeat the point.
    #
    # IMPORTANT: only the DISPLAY lives inside the fragment. Buttons inside a
    # fragment re-run just that fragment, so setting session_state here would
    # never propagate to Tab 3 -- which is why the email tab kept saying "no
    # investigation" after an incident was imported. The selector and the LOAD
    # button therefore sit outside, where a click triggers a normal full rerun.
    @st.fragment(run_every=3.0)
    def render_live_attack():
        recent = list_recent_sessions(10)

        st.markdown("#### Two-Device Phone Incidents")
        st.caption(
            "Live view of sessions recorded by the phone backend (server.py). "
            "Refreshes every few seconds."
        )

        if not recent:
            st.info(
                "No phone sessions recorded yet. Start the backend with "
                "`run_demo.bat` (or `python server.py`), then open /victim and "
                "/attacker on two phones."
            )
            return

        latest = recent[0]
        attacked = latest["attack"] is not None
        colour = "#ff4d6d" if attacked else "#00ff88"
        label = latest["attack"] or "honest channel"
        st.markdown(
            f'<div class="msg-panel" style="margin:0.3rem 0 0.5rem 0;">'
            f'<div class="metric-label">LATEST PHONE ATTACK</div>'
            f'<div class="mono" style="color:{colour};font-size:1.05rem;margin-top:0.3rem;">'
            f'{latest["code"]} &middot; {label} &middot; {latest["verdict"]} '
            f'({latest["corrupted"]}/{latest["total_bits"]} bits)</div>'
            f'<div class="mono" style="color:#9aa4b1;font-size:0.85rem;margin-top:0.25rem;">'
            f'signed: {latest["message"]}</div>'
            f"</div>",
            unsafe_allow_html=True,
        )

        preview = get_phone_report_data(latest["code"])
        if preview:
            pc1, pc2 = st.columns(2)
            with pc1:
                st.markdown(f"**Signed:** `{preview['original_message']}`")
            with pc2:
                st.markdown(f"**Received:** `{preview['received_message']}`")
            if preview.get("attack_type"):
                st.caption(preview["attack_description"])
                st.caption(
                    f"Bit verdict {preview['bit_verdict']} · "
                    f"{preview['error_rate']*100:.2f}% error · "
                    f"posture {preview['posture']}"
                )
            witness = preview.get("witness")
            if witness and witness.get("verdict"):
                st.caption(f"Quantum witness: {witness['verdict']}")

    render_live_attack()

    # --- Selector + action, deliberately OUTSIDE the fragment --------------
    recent_all = list_recent_sessions(10)
    if recent_all:
        options = [
            f"{r['code']}  |  {r['message'][:20]}  |  {r['attack'] or 'honest'}  |  "
            f"{r['corrupted']}/{r['total_bits']} bits"
            for r in recent_all
        ]
        code = st.selectbox("Incident to import", options, index=0).split("|")[0].strip()

        if st.button("LOAD PHONE INCIDENT", type="primary", key="load_phone"):
            data = get_phone_report_data(code)
            if not data:
                st.error(f"Could not read session {code}.")
            else:
                # Stage 1: the offline report is built immediately so the
                # session overview appears at once. TinyFish runs as a separate
                # background stage below; blocking on it here made the whole
                # panel freeze for several seconds and looked broken.
                base_report = InvestigationReport.create_from_phone_session(data)
                problems = base_report.validate()
                if problems:
                    st.error("Report failed validation: " + "; ".join(problems))
                else:
                    st.session_state["investigation_report"] = base_report
                    st.session_state["phone_session"] = data
                    st.session_state["research_pending"] = True
                    st.session_state["research_started"] = False
                    st.session_state["research_code"] = code
                    st.success(
                        f"Session overview loaded: {data['corrupted_bits']}/"
                        f"{data['total_bits']} bits corrupted, posture "
                        f"{base_report.risk_posture}. Research running now."
                    )

    # --- Stage 2: TinyFish research, run ONCE ------------------------------
    # The offline report is already on screen while this runs, so the panel
    # never blocks on the network.
    #
    # Two bugs are avoided here deliberately:
    #   1. st.rerun(scope="fragment") is only legal DURING a fragment rerun.
    #      Calling it on the fragment's first execution raised
    #      StreamlitInvalidLayoutContextError.
    #   2. Doing the research inside a @st.fragment(run_every=...) re-queried
    #      TinyFish on every tick until a terminal status came back, burning
    #      API calls and potentially yielding a different report each time.
    # A one-shot guarded by a session flag is simpler and correct.
    if st.session_state.get("research_pending") and not st.session_state.get("research_started"):
        target_code = st.session_state.get("research_code")
        data = get_phone_report_data(target_code) if target_code else None
        if not data:
            st.session_state["research_pending"] = False
        else:
            st.session_state["research_started"] = True
            status_slot = st.empty()
            status_slot.info("TinyFish researching this attack type...")
            try:
                enriched = agent.investigate_phone_session(data)
            except Exception as exc:
                enriched = InvestigationReport.create_from_phone_session(data)
                enriched.known_limitations.append(
                    f"Live research could not be completed for this incident: {exc}")
                enriched.research_status = "error"
            status_slot.empty()
            st.session_state["investigation_report"] = enriched
            st.session_state["phone_session"] = data
            st.session_state["research_pending"] = False

    st.markdown("---")

    if last is None:
        # Not a dead end. The phone demo produces incidents without Tab 1, so
        # point the user at that path instead of telling them to go run a
        # session they may not have come here to run.
        phone_ready = bool(list_recent_sessions(1))
        if phone_ready:
            st.info(
                "No dashboard session in Tab 1, but phone-demo incidents are "
                "available above. Use **LOAD PHONE INCIDENT** to import one, or "
                "run a session in Tab 1 for the dashboard's own detector."
            )
        else:
            st.info(
                "No investigation source yet. Either run a quantum session in "
                "Tab 1, or start the phone backend (`run_demo.bat`) and import "
                "a two-device incident above."
            )
    else:
        inv_col1, inv_col2 = st.columns([1, 2])
        with inv_col1:
            investigate_clicked = st.button("INVESTIGATE SESSION", type="primary")

        if investigate_clicked:
            with st.spinner("Q-Intel interpreting session outputs and querying TinyFish research tools..."):
                try:
                    report = agent.investigate_session(last, CALIBRATED_THRESHOLD)
                    st.session_state["investigation_report"] = report
                    st.success("Investigation complete! Structured report synthesized.")
                except Exception as e:
                    st.error(f"Investigation failed: {str(e)}")

    # The report renders for EITHER source.
    #
    # This used to sit inside the `else:` branch above, so it only rendered
    # when Tab 1 had a session. A phone-demo incident built a perfectly good
    # report that was then never displayed -- the user saw "Session overview
    # loaded" followed by nothing. Reading the session state here instead of
    # inside either branch fixes it for both paths and removes the coupling.
    report: Optional[InvestigationReport] = st.session_state.get("investigation_report")
    render_report_body(report)

# ==============================================================================
# TAB 3: EMAIL REPORT
# ==============================================================================
with tab_email:
    st.markdown("### Transactional Security Email Reporting")
    st.caption("Generate, inspect, and dispatch high-fidelity HTML security reports via Resend API.")

    report: Optional[InvestigationReport] = st.session_state.get("investigation_report")

    if report is None:
        phone_ready = list_recent_sessions(1)
        if phone_ready:
            st.info(
                "No report loaded yet. Go to **Tab 2 (Q-Intel)**, choose a "
                "two-device phone incident, and press **LOAD PHONE INCIDENT** "
                "-- or run a dashboard session in Tab 1 and press "
                "**INVESTIGATE SESSION**."
            )
            latest = phone_ready[0]
            st.caption(
                f"Most recent available incident: {latest['code']} "
                f"({latest['attack'] or 'honest'}, "
                f"{latest['corrupted']}/{latest['total_bits']} bits corrupted)"
            )
        else:
            st.info(
                "No report loaded yet. Generate one in Tab 2 first -- either "
                "from a phone-demo incident or from a dashboard session in Tab 1."
            )
    else:
        cfg_col1, cfg_col2, cfg_col3 = st.columns([1, 1.5, 1])
        with cfg_col1:
            report_style = st.selectbox("Report Style", ["Simple Explanation", "Technical Report"], index=0)
            style_key = "simple" if report_style == "Simple Explanation" else "technical"

        with cfg_col2:
            recipient_email = st.text_input(
                "Recipient Email",
                placeholder="analyst@enterprise.com, soc-lead@company.com",
                help="One address, or several separated by commas. Everyone lands in the To: field, "
                     "so they can see each other. Delivery to arbitrary addresses requires a "
                     "sending domain you own, verified in Resend -- the shared onboarding@resend.dev "
                     "sender can only reach the account owner's own address.",
            )

        with cfg_col3:
            st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
            refresh_preview = st.button("REFRESH PREVIEW")

        # Generate Email Bodies
        html_preview, text_preview = agent.generate_report_content(report, style=style_key)

        # Subject line preview
        subject_line = f"QCTD Investigation Report [{report.risk_posture}] - {report.report_id[:8]}"
        st.markdown(f"**Subject:** `{subject_line}`")

        # For phone incidents, restate the signed/received pair in the email
        # tab too. The whole point of the demo is that the recipient can SEE
        # what was tampered with, so it must not be buried in Tab 2.
        phone_data = st.session_state.get("phone_session")
        if phone_data:
            st.markdown("#### Tampered Message")
            p1, p2 = st.columns(2)
            with p1:
                st.markdown(f"**Signed:** `{phone_data['original_message']}`")
            with p2:
                st.markdown(f"**Received:** `{phone_data['received_message']}`")
            st.caption(
                f"Session {phone_data['session_code']} · attack "
                f"{phone_data['attack_type'] or 'none'} · "
                f"{phone_data['corrupted_bits']}/{phone_data['total_bits']} bits corrupted "
                f"· posture {phone_data['posture']}"
            )

        # Render Live HTML Preview
        with st.expander("Rendered Email Preview", expanded=True):
            st.components.v1.html(html_preview, height=520, scrolling=True)

        with st.expander("Plain-Text Alternative Preview"):
            st.code(text_preview, language="text")

        # Send Controls
        st.markdown("---")
        can_send = True
        send_error_reasons = []

        if not agent.email_available:
            can_send = False
            send_error_reasons.append("RESEND_API_KEY is not configured and no SMTP credentials were found.")

        parsed_recipients, invalid_recipients = parse_recipients(recipient_email)

        if not parsed_recipients:
            can_send = False
            if invalid_recipients:
                send_error_reasons.append(
                    "Invalid recipient address(es): " + ", ".join(invalid_recipients)
                )
            else:
                send_error_reasons.append("A valid recipient email address is required.")

        # Preflight: warn BEFORE a doomed send when the Resend sender is the
        # shared onboarding domain. Resend silently restricts that sender to
        # the account owner's own address, so any other recipient returns 403.
        # Detecting it here turns a confusing mid-demo failure into a clear
        # instruction.
        sender_addr = agent.email_service.sender_address or ""
        sender_is_shared = (
            agent.email_service.transport == "resend"
            and sender_addr.lower().endswith("@resend.dev")
        )
        owner_only = [a for a in parsed_recipients if a.lower() != (agent.email_service.account_email or "").lower()]
        if sender_is_shared and owner_only:
            st.warning(
                "**Sending to anyone other than the Resend account owner will fail (403).**\n\n"
                f"The sender is `{sender_addr}`, which is Resend's shared onboarding domain. "
                "Resend only lets it deliver to the account owner's own address.\n\n"
                "**Two ways to fix:**\n"
                "1. Verify your own domain at https://resend.com/domains, then set "
                "`REPORT_FROM_EMAIL=\"QCTD Reports <reports@yourdomain.com>\"` in `.env`. "
                "No code change needed.\n"
                "2. Or use the SMTP fallback (no domain required) — set `SMTP_HOST`, "
                "`SMTP_USER` and `SMTP_PASSWORD` in `.env`, and leave `RESEND_API_KEY` empty. "
                "For Gmail, use a 16-character App Password.\n\n"
                "Sending to your own address works right now."
            )

        # Check for duplicate send
        dispatch_key = f"{report.report_id}_{recipient_email.strip()}_{style_key}"
        already_sent = dispatch_key in st.session_state["email_dispatches"]

        send_col1, send_col2 = st.columns([1, 2])
        with send_col1:
            send_clicked = st.button(
                "SEND EMAIL REPORT",
                type="primary",
                disabled=not can_send,
                help="Sends the report directly to the recipient using Resend API." if can_send else "; ".join(send_error_reasons),
            )

        with send_col2:
            if not can_send:
                st.caption(f"Sending disabled: {'; '.join(send_error_reasons)}")
            elif already_sent:
                prior_id = st.session_state['email_dispatches'][dispatch_key]
                st.info(f"Report already dispatched to {recipient_email} (Message ID: {prior_id}). Click Run Session or Refresh to send a new report.")

        if send_clicked and can_send:
            if already_sent:
                st.warning("Prevented duplicate send: this exact report version was already sent to this recipient.")
            else:
                with st.spinner("Dispatching email via Resend API..."):
                    res = agent.send_email_report(report, recipient_email.strip(), style=style_key)
                    if res.success:
                        st.session_state["email_dispatches"][dispatch_key] = res.message_id or "delivered"
                        st.success(f"Report successfully dispatched! Provider Message ID: {res.message_id}")
                    else:
                        st.error(f"Email dispatch failed: {res.error_message}")

# ==============================================================================
# TAB 4: TECHNICAL EVIDENCE
# ==============================================================================
with tab_evidence:
    st.markdown("### Technical Evidence & Verification Architecture")
    st.caption("Deep-dive inspection of probability distributions, statistical divergences, and protocol mechanics.")

    if last is None:
        st.info("Awaiting session run. Run a session in Tab 1 to inspect distributions.")
    else:
        exp_p = counts_to_probs(last["expected"])
        obs_p = counts_to_probs(last["observed"])
        keys = _bitstrings()

        # Detailed Bin Breakdown Table
        st.markdown("#### Measurement Bin Distribution Table")
        table_data = []
        for k in keys:
            o_prob = obs_p[k]
            e_prob = exp_p[k]
            diff = o_prob - e_prob
            safe_e = max(e_prob, 0.01)
            bin_chi_sq = (diff ** 2) / safe_e
            table_data.append({
                "Bitstring (c2 c1 c0)": k,
                "Expected Probability": f"{e_prob:.4f}",
                "Observed Probability": f"{o_prob:.4f}",
                "Residual (Obs - Exp)": f"{diff:+.4f}",
                "Chi-sq Bin Contribution": f"{bin_chi_sq:.5f}",
            })
        st.table(table_data)

        st.markdown("#### Decision Matrix Architecture")
        st.markdown(
            """
            The architecture couples two independent assessment signals:
            - **Security State (Fidelity Check):** Directly tests teleported-bit fidelity on clbit 2. If error rate exceeds 11%, security assumptions are breached regardless of whether an active attack pattern is recognized.
            - **Threat Detector (Distributional Anomaly):** Computes chi-squared distance across all 8 multi-qubit measurement bins relative to the honest reference. Values exceeding `CALIBRATED_THRESHOLD = 0.0253` flag active channel perturbation.
            - **Risk Posture:** Synthesized via a 2x2 decision matrix to differentiate between degraded hardware noise (`WEAK`) and active hostile tampering (`STRONG + ALERT` / `CRITICAL`).
            """
        )
