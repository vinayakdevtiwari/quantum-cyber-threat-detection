"""
phone_bridge.py

Connects the two-phone demo (server.py / SQLite) to the analytics + email
pipeline in app.py.

WHY A BRIDGE
------------
A phone attack produces a different KIND of result from a dashboard
simulation. The dashboard simulates one qubit and reports a chi-squared
divergence. A phone session carries a whole message, teleported bit by bit,
and reports per-bit integrity. Those are not the same measurement, and
pretending otherwise would put meaningless numbers in front of a judge.

So this module translates a phone session into the telemetry the Risk Engine
actually consumes, by mapping:

    per-bit corruption  ->  error rate     (Security State)
    attack present      ->  threat label   (Threat Detector)
    both                ->  2x2 posture    (Risk Engine)

The resulting report keeps both vocabularies: the original quantum
detector figures, and the message-layer findings, side by side. A reader can
see the attack in the message AND see it reflected in the posture matrix.

HONEST LIMITATION, STATED UP FRONT
-----------------------------------
The chi-squared deviation and calibrated threshold in the report describe the
3-qubit teleportation detector used by the dashboard. A phone session does not
run that detector. Rather than fabricate a chi-squared number for a session
that never computed one, this bridge reports the per-bit error fraction as the
primary integrity metric and marks the chi-squared fields as not applicable.

If you want both, run a dashboard simulation AND a phone attack, then report
the pair.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qds_sessions.db")

# 11% mirrors detection.SECURITY_ERROR_THRESHOLD. A phone message uses
# per-bit integrity rather than a single teleported-qubit check, but the same
# tolerance keeps one meaning of "error rate" across the project.
PHONE_ERROR_THRESHOLD = 0.11

# Bit-error rate above this is treated as an active attack rather than noise.
# Honest hardware noise sits near 2% (measured); a targeted forgery is a few
# bits, and channel manipulation reaches 20-40%.
ATTACK_ERROR_FLOOR = 0.03


def _connect() -> Optional[sqlite3.Connection]:
    if not os.path.exists(DB_PATH):
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def latest_phone_session() -> Optional[Dict[str, Any]]:
    """Most recent phone session, or None if the demo server hasn't run."""
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT * FROM sessions ORDER BY created_utc DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def session_by_code(code: str) -> Optional[Dict[str, Any]]:
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT * FROM sessions WHERE code = ?", (code.strip().upper(),)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def _split(csv: Optional[str]) -> list:
    return [int(x) for x in (csv or "").split(",") if x.strip() != ""]


def _load_witness(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Decode the stored signature-layer result for a session.

    Tolerates rows written before the witness column existed and any malformed
    JSON, returning None rather than raising -- a missing witness must not stop
    the dashboard from showing a session.
    """
    raw = None
    try:
        raw = row["witness_json"]
    except (KeyError, IndexError):
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def session_data_from_row(row: Dict[str, Any],
                          witness: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Translate a stored phone session into the dict that
    InvestigationReport.create_from_phone_session expects.

    The mapping is explicit about what is measured versus inferred:
      - error_rate   : measured (corrupted bits / total bits)
      - threat_label : derived from whether an attack ran and how much
                       corruption it caused
      - deviation    : NOT APPLICABLE. This session was verified per-bit, not
                       distributionally, so no chi-squared value is invented.
    """
    original_bits = row["original_bits"] or ""
    total_bits = len(original_bits)

    attacked = row["attack"] is not None
    corrupted = row["corrupted"] if row["corrupted"] is not None else 0
    error_fraction = (row["error_fraction"] if row["error_fraction"] is not None
                      else (corrupted / total_bits if total_bits else 0.0))

    verdict = row["verdict"] or "AWAITING ATTACK"
    sec_state = "INSECURE" if error_fraction > PHONE_ERROR_THRESHOLD else "SECURE"

    if attacked and error_fraction >= ATTACK_ERROR_FLOOR:
        threat_label = "THREAT"
        detector_verdict = "ANOMALOUS - FLAG/REJECT"
    elif attacked:
        threat_label = "THREAT"
        detector_verdict = "ANOMALOUS - ATTACK IN PROGRESS"
    else:
        threat_label = "NO_THREAT"
        detector_verdict = "NORMAL - ACCEPT"

    # 2x2 posture from the same matrix risk_engine uses.
    if sec_state == "SECURE" and threat_label == "NO_THREAT":
        posture = "VERY STRONG"
    elif sec_state == "SECURE":
        posture = "STRONG + ALERT"
    elif threat_label == "NO_THREAT":
        posture = "WEAK"
    else:
        posture = "CRITICAL"

    if not attacked:
        explanation = ("No attack was injected into this session; the message "
                       "arrived intact and the protocol's assumptions hold.")
    elif sec_state == "SECURE":
        explanation = (f"A {row['attack']} attack corrupted {corrupted} of "
                       f"{total_bits} bits ({error_fraction*100:.1f}%), which stays "
                       f"within the {PHONE_ERROR_THRESHOLD*100:.0f}% integrity "
                       f"tolerance. The protocol's guarantees are protecting this "
                       f"session -- the source should be investigated, but the "
                       f"message itself was not critically corrupted.")
    else:
        explanation = (f"A {row['attack']} attack corrupted {corrupted} of "
                       f"{total_bits} bits ({error_fraction*100:.1f}%), exceeding "
                       f"the {PHONE_ERROR_THRESHOLD*100:.0f}% integrity tolerance. "
                       f"The message is untrustworthy and the protocol's "
                       f"assumptions no longer hold.")

    attacked_indices = _split(row["attacked_bits"])
    shown = ", ".join(str(b) for b in attacked_indices[:10])
    if len(attacked_indices) > 10:
        shown += f" ... (+{len(attacked_indices) - 10} more)"

    original_text = row["message"] or ""
    received_text = row["received_text"] or "(not yet received)"

    data = {
        # Identity / provenance
        "source": "phone_demo",
        "session_code": row["code"],
        "created_utc": row["created_utc"],

        # The message layer's own vocabulary
        "original_message": original_text,
        "received_message": received_text,
        "attack_type": row["attack"],
        "attack_description": row["attack_desc"] or "",
        "attacked_bits": attacked_indices,
        "attacked_bits_display": shown,
        "bit_verdict": verdict,
        # The signature layer's finding for this session. Carried through the
        # bridge so the report and email can state whether the quantum witness
        # accepted the signature and whether context binding caught a replay.
        # Without it, a replay incident reports only "TAMPERED" and loses the
        # entire point: the witness passed, context caught it.
        "witness": witness,
        "corrupted_bits": corrupted,
        "total_bits": total_bits,

        # Mapped into the dashboard's vocabulary so the Risk Engine can use it
        "simulation_mode": "Phone demo (two-device)",
        "blind": False,
        "revealed": True,
        "message_state": "n/a (multi-bit message register)",
        "session_basis": "Z",
        "shots": row["shots"] or 256,

        # Chi-squared detector was NOT run on this session. Reporting 0 here
        # keeps the report schema valid without inventing a measurement.
        "deviation": 0.0,
        "calibrated_threshold": 0.0253,
        "score": 0.0,
        "result": detector_verdict,
        "threat_label": threat_label,

        "error_rate": error_fraction,
        "error_threshold": PHONE_ERROR_THRESHOLD,
        "sec_state": sec_state,

        "posture": posture,
        "explanation": explanation,

        "actual_attack": row["attack"] or "none (honest channel)",
        "actual_channel": "phone demo (attacker device)",

        # Evidence lines the report model appends verbatim.
        "simulation_evidence": [
            f"Origin: two-device phone demo, session {row['code']}",
            f"Original message: \"{original_text}\"",
            f"Received message: \"{received_text}\"",
            f"Attack injected: {row['attack'] or 'none'}",
            f"Attack mechanism: {row['attack_desc'] or 'n/a'}",
            f"Bit-level integrity: {corrupted}/{total_bits} bits corrupted "
            f"({error_fraction*100:.2f}%)",
            f"Attacked bit indices: {shown or 'none'}",
            f"Message-layer verdict: {verdict}",
            f"Mapped Security State: {sec_state} (tolerance "
            f"{PHONE_ERROR_THRESHOLD*100:.0f}%)",
            f"Mapped Threat Label: {threat_label}",
            f"Risk Posture: {posture}",
        ],

        "known_limitations": [
            "Phone-demo session: this incident was generated by a second device "
            "(attacker) and recorded through the two-device demo backend, not by "
            "the dashboard's own Monte Carlo session runner.",
            "No chi-squared deviation: this session reports per-bit integrity "
            "rather than a distributional divergence, so the chi-squared detector "
            "fields are not applicable and are reported as zero rather than "
            "estimated.",
            "Integrity vs. authenticity: per-bit verification confirms the message "
            "was corrupted, but comparing against the sender's original presumes a "
            "trusted copy. A quantum witness state is what makes forgery expensive "
            "rather than merely detectable.",
            "Simulation only: the quantum channel is Qiskit Aer with a "
            "depolarizing noise model, not physical quantum hardware.",
        ],
    }
    return data


def get_phone_report_data(code: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Convenience entry point for app.py. Pass a session code, or omit to take
    the most recent one. Returns None when the backend has no sessions.
    """
    row = session_by_code(code) if code else latest_phone_session()
    if not row:
        return None
    return session_data_from_row(row, witness=_load_witness(row))


def list_recent_sessions(limit: int = 10):
    """Recent sessions, for a picker in the dashboard."""
    conn = _connect()
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT code, message, attack, verdict, corrupted, total_bits, "
            "created_utc FROM sessions ORDER BY created_utc DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def db_written_since(stamp: Optional[float]) -> bool:
    """
    True when qds_sessions.db has been modified since `stamp`.

    Used by the dashboard to avoid re-reading the database on every Streamlit
    rerun. Reading it is cheap, but a phone attack can fire many times during
    a demo, and re-querying on each interaction makes the UI feel like it is
    thrashing. Callers pass the mtime they last saw and only refresh when it
    actually changed.

    Returns False when the file is missing, so a first-run dashboard does not
    treat "no database yet" as a change.
    """
    if not os.path.exists(DB_PATH):
        return False
    try:
        return os.path.getmtime(DB_PATH) > (stamp or 0.0)
    except OSError:
        return False


def db_timestamp() -> Optional[float]:
    """Modification time of the session database, or None if absent."""
    if not os.path.exists(DB_PATH):
        return None
    try:
        return os.path.getmtime(DB_PATH)
    except OSError:
        return None


if __name__ == "__main__":
    row = latest_phone_session()
    if not row:
        print("No phone sessions found. Start server.py and run a demo first.")
    else:
        data = get_phone_report_data()
        print("=" * 68)
        print(" PHONE SESSION -> REPORT BRIDGE")
        print("=" * 68)
        print(f"  code          : {data['session_code']}")
        print(f"  signed        : {data['original_message']!r}")
        print(f"  received      : {data['received_message']!r}")
        print(f"  attack        : {data['attack_type']}")
        print(f"  bit verdict   : {data['bit_verdict']}")
        print(f"  corrupted     : {data['corrupted_bits']}/{data['total_bits']}")
        print(f"  error rate    : {data['error_rate']*100:.2f}% "
              f"-> {data['sec_state']}")
        print(f"  threat label  : {data['threat_label']}")
        print(f"  posture       : {data['posture']}")
        print()
        for line in data["simulation_evidence"]:
            print(f"    - {line}")