"""
qds_live.py

Two-role live demo of the message layer.

    VICTIM   (phone A / window 1) - sends a signed message, sees the
             received text and the per-bit verification result.
    ATTACKER (phone B / window 2) - joins with the session code and
             manipulates the bits in transit.

Both roles live in ONE Streamlit app because Streamlit has no separate
routes. The role is chosen at the top of the page, and the two browser
windows (or two phones) talk to each other through a session dictionary.

WHY A SESSION DICTIONARY
------------------------
Streamlit's st.session_state is per-browser, so the attacker window could not
see what the victim window created. A module-level dict keyed by a short
session code is shared across browsers served by the same process, which is
what lets two devices collaborate.

Known limitation: this assumes both clients reach the SAME server process.
On a single-instance deployment that holds. If you scale to multiple
instances, replace this dict with shared storage (Redis, or a tiny database)
-- the rest of the app does not change.

Run:
    streamlit run qds_live.py
"""

import random
import string
import time

import streamlit as st

from message_layer import (
    transmit_message, verify_message, text_to_bits, bits_to_text,
    ATTACK_LABELS, ATTACK_NONE, ATTACK_FORGERY, ATTACK_REPLAY,
    ATTACK_CHANNEL, ATTACK_IMPERSONATION, MAX_MESSAGE_CHARS, DEFAULT_NOISE_MODEL,
)

# Sessions survive Streamlit reruns but NOT a process restart. That is
# acceptable for a live demo and keeps the state layer trivial.
#
# This MUST be a module-level dict, not st.session_state.
#
# st.session_state is scoped to ONE browser session, so the victim wrote its
# session into its own dict and the attacker read from a different, empty one.
# The symptom was total: no session ever crossed between the two windows, so
# nothing could join and no message could be received. The docstring above has
# always said the opposite of what the code did; this is now what it describes.
#
# Streamlit re-executes this module on every interaction, but a module-level
# name is rebuilt only when the process starts, so the dict survives reruns --
# which is the property that is actually needed here.
SESSIONS = {}

PRESETS = [
    "TRANSFER $5000",
    "AUTHORIZE OFFICER SINGH",
    "PAYROLL UPDATE OK",
    "SECRET KEY ALPHA7",
]

STYLE = """
<style>
.qds-banner {
    border: 1px solid rgba(0,255,136,0.28);
    background: linear-gradient(135deg, rgba(0,255,136,0.07), #10141b 55%);
    padding: 1rem 1.2rem; margin-bottom: 1rem;
}
.qds-title { font-family: "Share Tech Mono", monospace; color: #00ff88;
    font-size: 1.15rem; letter-spacing: 0.14em; }
.qds-sub { color: #8b949e; font-size: 0.86rem; margin-top: 0.3rem; }
.msg-panel { border: 1px solid rgba(0,255,136,0.2); background: #12161e;
    padding: 0.9rem 1.1rem; margin: 0.5rem 0; border-radius: 6px; }
.msg-label { font-family: "Share Tech Mono", monospace; font-size: 0.68rem;
    text-transform: uppercase; letter-spacing: 0.16em; color: #8b949e; }
.msg-value { font-family: "Share Tech Mono", monospace; font-size: 1.05rem;
    color: #e6edf3; margin-top: 0.35rem; word-break: break-all; }
.msg-value.bad { color: #ff4d6d; }
.msg-value.good { color: #00ff88; }
.code-chip { font-family: "Share Tech Mono", monospace; background: #0b0e14;
    border: 1px solid #00ff88; color: #00ff88; padding: 0.35rem 0.8rem;
    border-radius: 4px; font-size: 1.1rem; letter-spacing: 0.16em;
    display: inline-block; }
.verdict-ok, .verdict-suspect, .verdict-bad { padding: 0.4rem 1rem;
    border-radius: 4px; font-family: "Share Tech Mono", monospace;
    letter-spacing: 0.1em; display: inline-block; }
.verdict-ok { background: rgba(0,255,136,0.15); color: #00ff88; border: 1px solid #00ff88; }
.verdict-suspect { background: rgba(255,196,0,0.15); color: #ffc400; border: 1px solid #ffc400; }
.verdict-bad { background: rgba(255,45,85,0.15); color: #ff4d6d; border: 1px solid #ff2d55; }
table.qds-bits { font-family: "Share Tech Mono", monospace; font-size: 0.8rem; }
</style>
"""


def new_code() -> str:
    return "QCTD-" + "".join(random.choice(string.digits) for _ in range(4))


def get_session(code: str):
    return SESSIONS.get(code)


def render_message_panel(label: str, value: str, tone: str = ""):
    cls = f"msg-value {tone}" if tone else "msg-value"
    st.markdown(
        f'<div class="msg-panel"><div class="msg-label">{label}</div>'
        f'<div class="{cls}">{value or "(empty)"}</div></div>',
        unsafe_allow_html=True,
    )


def render_bit_table(verification: dict, max_rows: int = 60):
    """Show the per-bit fidelity table, corrupted rows first."""
    rows = verification["bits"]
    bad = [r for r in rows if not r["ok"]]
    good = [r for r in rows if r["ok"]]

    if not bad:
        st.success("Every bit matches the signed original. No tampering detected.")
        return

    st.markdown(f"**{len(bad)} corrupted bit(s)** — expected vs received:")
    data = [{"bit": r["index"], "expected": r["expected"],
             "received": r["received"], "status": "CORRUPT"} for r in bad[:max_rows]]
    st.dataframe(data, use_container_width=True, hide_index=True)
    if len(bad) > max_rows:
        st.caption(f"...and {len(bad) - max_rows} more.")
    st.caption(f"{len(good)} bits matched correctly and are omitted.")


# ---------------------------------------------------------------------------
st.set_page_config(page_title="QDS Live Bit Manipulation", page_icon="🔐",
                   layout="wide")
st.markdown(STYLE, unsafe_allow_html=True)

st.markdown(
    '<div class="qds-banner">'
    '<div class="qds-title">QDS LIVE — BIT MANIPULATION &amp; ATTACK INJECTION</div>'
    '<div class="qds-sub">Quantum message transit · real Qiskit simulation · '
    'per-bit verification</div></div>',
    unsafe_allow_html=True,
)

# --- role selection --------------------------------------------------------
role = st.radio("Your role", ["VICTIM (send & verify)", "ATTACKER (manipulate bits)"],
                index=0, horizontal=True)

if role.startswith("VICTIM"):
    st.subheader("Victim — send a signed message")

    if "code" not in st.session_state:
        st.session_state.code = new_code()

    text = st.text_input(
        f"Message to sign (max {MAX_MESSAGE_CHARS} characters)",
        value=PRESETS[0], max_chars=MAX_MESSAGE_CHARS,
    )
    shots = st.slider("Shots per bit", 64, 512, 256, step=64)

    c1, c2 = st.columns([1, 2])
    with c1:
        send = st.button("SIGN & TRANSMIT", type="primary")
    with c2:
        st.caption("Signs the message, teleports each bit over the quantum channel, "
                   "then verifies what arrived.")

    if send:
        try:
            bits = text_to_bits(text)
        except ValueError as e:
            st.error(str(e))
        else:
            code = st.session_state.code
            SESSIONS[code] = {
                "message": text.strip(),
                "bits": bits,
                "attacked": None,
                "received": None,
                "verification": None,
                "attack_description": "Message signed and transmitted. No attack yet.",
                "shots": shots,
                "created": time.time(),
            }
            st.session_state.code = new_code()  # roll to a fresh code for the next send
            st.session_state.last_code = code

    code = st.session_state.get("last_code")
    if code and get_session(code):
        st.success(f"Session created. Share this code with the attacker:  `{code}`")
        sess = get_session(code)
        render_message_panel("SIGNED (original)", sess["message"], "good")
        st.caption(f"{len(sess['bits'])} bits · {len(sess['bits']) * 3} qubits · "
                   f"{sess['attack_description']}")
        if sess.get("verification"):
            v = sess["verification"]
            tone = "bad" if v["corrupted_count"] else "good"
            render_message_panel("RECEIVED (as decoded)", sess["received"], tone)
            cls = {"VERIFIED": "verdict-ok", "SUSPECT": "verdict-suspect"}.get(
                v["status"], "verdict-bad")
            st.markdown(
                f'<div class="{cls}">{v["status"]}</div> '
                f'<span style="color:#8b949e;font-family:monospace">'
                f'{v["corrupted_count"]}/{v["total_bits"]} bits corrupted</span>',
                unsafe_allow_html=True,
            )
            with st.expander("Per-bit verification"):
                render_bit_table(v)

    st.markdown("---")
    st.caption("Open the same URL in a second window or phone, switch to "
               "ATTACKER, and enter the session code to manipulate the bits.")

else:
    st.subheader("Attacker — manipulate the bits in transit")

    code_input = st.text_input("Session code", placeholder="QCTD-0000").strip().upper()
    joined = st.button("JOIN SESSION")
    if joined:
        if get_session(code_input):
            st.session_state.attacker_code = code_input
            st.success(f"Joined session {code_input}")
        else:
            st.error("No session with that code. Ask the victim for the code.")

    code = st.session_state.get("attacker_code")
    if code and get_session(code):
        sess = get_session(code)
        n_bits = len(sess["bits"])
        render_message_panel("TARGET MESSAGE (what you will attack)", sess["message"], "")

        attack = st.selectbox("Attack type", list(ATTACK_LABELS.keys()),
                              format_func=lambda k: ATTACK_LABELS[k])

        target_text = ""
        substitute = None
        if attack == ATTACK_FORGERY:
            st.caption("Pick the exact bits to invert. This is the surgical, "
                       "traceable corruption.")
            target_text = st.text_input("Bit indices to flip (comma separated)",
                                        value="40,41,42,43")
        if attack == ATTACK_REPLAY:
            substitute = st.text_input("Replacement message", value="PAYROLL PENDING")
        if attack == ATTACK_CHANNEL:
            st.caption("Randomised multi-bit corruption — the 'garbage' case.")

        if st.button("INJECT ATTACK", type="primary"):
            targets = None
            if attack == ATTACK_FORGERY and target_text:
                try:
                    targets = [int(x) for x in target_text.split(",") if x.strip()]
                except ValueError:
                    targets = None
            result = transmit_message(
                sess["message"], attack=attack, seed=random.randint(1, 10**6),
                target_bits=targets, substitute=substitute,
                shots=sess.get("shots", 256),
            )
            sess["attacked"] = result["attacked_bits"]
            sess["received"] = result["received_text"]
            sess["verification"] = result["verification"]
            sess["attack_description"] = result["attack_description"]

        if sess.get("verification"):
            v = sess["verification"]
            st.markdown("**Attack result on the victim's channel**")
            render_message_panel("CORRUPTED TEXT", sess["received"], "bad")
            cls = {"VERIFIED": "verdict-ok", "SUSPECT": "verdict-suspect"}.get(
                v["status"], "verdict-bad")
            st.markdown(
                f'<div class="{cls}">{v["status"]}</div> '
                f'<span style="color:#8b949e;font-family:monospace">'
                f'{v["corrupted_count"]}/{v["total_bits"]} bits corrupted</span>',
                unsafe_allow_html=True,
            )
            st.caption("Switch to the VICTIM window and refresh to see this reflected there.")
            with st.expander("Per-bit verification"):
                render_bit_table(v)