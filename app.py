"""
app.py

Streamlit demo for the QDS threat detection framework.
Run with: streamlit run app.py

UI: SOC-themed dashboard (design by teammate).
Backend: Threat Detector + Security State + Risk Engine, with manual and
blind-test modes.
"""

import random
from datetime import datetime, timezone

import streamlit as st

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

# Value from calibrate.py -- rerun that script and update this if you
# change shots/trials/message state. Calibrated against a POOL of honest
# sessions under both normal and degraded channel conditions AND both
# measurement bases (Z and X), so ordinary hardware noise -- and the
# basis a session happens to land on -- don't get mistaken for an attack.
# Re-calibrated after adding basis pooling: 5.0% FPR on honest sessions,
# ~50-52% per-session detection rate per attack type (expected -- each
# attack is a single Pauli error, visible in only one of the two bases;
# see the no-cloning-theorem discussion in chat for why this is correct
# behavior, not a regression, and why repeating sessions is the fix).
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
    padding-top: 1.4rem;
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
    padding: 1.4rem 1.2rem;
    color: #8b949e;
    background: rgba(22, 27, 34, 0.45);
    text-align: center;
    font-family: "Share Tech Mono", monospace;
}

.pipeline {
    margin-top: 1.4rem;
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

[data-testid="stMetric"] {
    background: #141922;
    border: 1px solid rgba(0, 255, 136, 0.18);
    padding: 0.6rem 0.8rem;
}
</style>
"""


def _bitstrings(num_bits: int = 3):
    return [format(i, f"0{num_bits}b") for i in range(2 ** num_bits)]


def counts_to_probs(counts: dict, num_bits: int = 3):
    total = max(sum(counts.values()), 1)
    keys = _bitstrings(num_bits)
    return {k: counts.get(k, 0) / total for k in keys}


def attack_kind_label(attack_key: str) -> str:
    if attack_key == "none":
        return "nominal QDS session"
    return ATTACK_LABELS.get(attack_key, attack_key).lower()


def render_posture_alert(posture: str, explanation: str, threat_label: str, sec_state: str):
    style, icon = POSTURE_STYLE[posture]
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


st.set_page_config(
    page_title="Quantum Cyber Threat Detection",
    page_icon=":satellite:",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(SOC_CSS, unsafe_allow_html=True)

now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
st.markdown(
    f"""
    <div class="soc-topbar">
      <div>
        <p class="soc-kicker">Quantum Cyber Threat Detection &middot; Team Project</p>
        <h1 class="soc-title">QUANTUM CYBER THREAT DETECTION</h1>
        <p class="soc-sub">QDS session security posture &middot; Team: Vinayak Dev Tiwari, Shivansh Tiwari, Ballabh Utkarsh Singh</p>
      </div>
      <div class="soc-meta">
        <div><span class="soc-dot"></span>SIMULATION MODE</div>
        <div>WATCHDESK {now_utc}</div>
        <div>SIMULATION NODE QDS-ALPHA</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

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
        help="Manual: you pick the scenario. Blind test: the system secretly "
             "randomizes the scenario -- you only see what's detected, then reveal "
             "the ground truth afterward.",
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
            help="Controls ONLY the baseline noise on the channel/hardware, independent "
                 "of any attack. 'Degraded' = noisy hardware with no attacker. Note: "
                 "even with 'Normal' selected, a successful attack can still push "
                 "Security State to INSECURE on its own -- the error rate reflects "
                 "attack effects too, not just channel noise.",
        )
    else:
        st.info("Attack type and channel condition will be chosen secretly.")
        attack_choice = None
        channel_choice = None

    shots = st.slider("Shots per session", 128, 2048, 512, step=128)

    st.markdown("---")
    run_clicked = st.button("RUN QDS SESSION", type="primary")
    st.caption("Honest baseline uses a cached 8192-shot expected distribution.")

if run_clicked:
    if demo_mode == "Blind test":
        actual_attack = random.choice(list(ATTACKS.keys()))
        actual_channel = random.choice(["Normal", "Degraded"])
    else:
        actual_attack = attack_choice
        actual_channel = channel_choice

    noise_model = DEGRADED_NOISE_MODEL if actual_channel == "Degraded" else DEFAULT_NOISE_MODEL

    # Measurement basis is randomized per session, the same way BB84-style
    # protocols randomize basis choice. A phase-flip attack (impersonation)
    # is invisible in the Z-basis but shows up as a bit-flip in the
    # X-basis, and vice versa for bit-flip-style attacks -- so no single
    # fixed basis can see every attack class. Randomizing it means every
    # attack type gets caught in *some* fraction of sessions, which is what
    # the calibrated threshold in calibrate.py now accounts for.
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

        # Security State (independent check)
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

last = st.session_state.get("last_run")

if last is None:
    st.markdown(
        '<div class="idle-panel">AWAITING SESSION &middot; SELECT PARAMETERS AND RUN QDS SESSION</div>',
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
            if st.button("REVEAL GROUND TRUTH"):
                st.session_state["last_run"]["revealed"] = True
                st.rerun()
        else:
            st.markdown(
                f"**Actual attack:** {ATTACK_LABELS.get(last['actual_attack'], last['actual_attack'])}  \n"
                f"**Actual channel:** {last['actual_channel']}"
            )
            correct_threat = (last["actual_attack"] != "none") == (last["threat_label"] == "THREAT")
            st.caption(
                f"Threat Detector called it {'correctly' if correct_threat else 'incorrectly'}. "
                "Security State reflects combined noise + attack effects on error rate, "
                "so it won't always map 1:1 to channel condition alone -- that's expected."
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
