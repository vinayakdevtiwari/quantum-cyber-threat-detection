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
tab_overview, tab_investigation, tab_email, tab_evidence = st.tabs([
    "1. Session Overview",
    "2. AI Investigation (Q-Intel)",
    "3. Email Report",
    "4. Technical Evidence",
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

# ==============================================================================
# TAB 2: AI INVESTIGATION (Q-INTEL)
# ==============================================================================
with tab_investigation:
    st.markdown("### Q-Intel AI Investigation Agent")
    st.caption(
        "Interprets real session measurements, queries TinyFish research endpoints for technical context, "
        "and synthesizes a verified, structured investigation report."
    )

    if last is None:
        st.info("Please run a quantum session in Tab 1 before launching an investigation.")
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

        report: Optional[InvestigationReport] = st.session_state.get("investigation_report")

        if report is not None:
            # Status Banner
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

            # Two columns for structured analysis
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

            # Optional Deep Research Module
            st.markdown("---")
            with st.expander("Initiate Deep Research (TinyFish Agent API)"):
                st.caption(
                    "Deep Research executes multi-iteration autonomous web research. "
                    "Note: This action calls the TinyFish Agent API and may consume account credits."
                )
                custom_q = st.text_input(
                    "Explicit Technical Research Question",
                    value=f"What are established statistical thresholding criteria for detecting eavesdropping in teleportation QDS with basis mismatch?",
                    help="Narrow, technical question regarding the simulated scenario.",
                )
                deep_clicked = st.button("EXECUTE DEEP RESEARCH")
                if deep_clicked:
                    if not agent.research_available:
                        st.error("Deep research requires a valid TINYFISH_API_KEY server-side.")
                    else:
                        with st.spinner("TinyFish Agent executing deep research iterations..."):
                            agent.run_deep_research(report, custom_q)
                            st.session_state["investigation_report"] = report
                            st.rerun()

# ==============================================================================
# TAB 3: EMAIL REPORT
# ==============================================================================
with tab_email:
    st.markdown("### Transactional Security Email Reporting")
    st.caption("Generate, inspect, and dispatch high-fidelity HTML security reports via Resend API.")

    report: Optional[InvestigationReport] = st.session_state.get("investigation_report")

    if report is None:
        st.info("Please generate an investigation in Tab 2 before creating an email report.")
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
