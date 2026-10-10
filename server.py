"""
server.py

Backend for the QDS bit-manipulation demo.

    /room     Group chat. Many participants, many attackers, one narrow
              transit window per message. This is the live demo.
    /victim   Single-shot page, kept as a fallback.
    /attacker Single-shot page, kept as a fallback.

The laptop runs this server and does all the quantum work. Phones are thin
clients: they send instructions (which attack, which bits) and render the
result. Qiskit cannot run on a phone, and should not -- the point of the demo
is that the quantum processing is centralized while the endpoints stay simple.

WHY SQLITE RATHER THAN A DICT
-----------------------------
A module-level dict is enough for one process, but it dies on restart. If the
server happens to bounce mid-demo, every live session is gone and the demo
stops. Worse, app.py runs as a *separate* Streamlit process and cannot read
another process's memory. A file-backed store lets the analytics dashboard
read the latest phone session without sharing a process.

Room membership and in-flight messages live in memory on purpose -- they are a
live demonstration, not a record. The forensic RESULT of every room message is
written to `sessions`, so the SOC evidence outlives the room.

Run:
    python server.py
"""

import os
import random
import json
import socket
import sqlite3
import string
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request, render_template
from flask_sock import Sock

from message_layer import (
    transmit_message, text_to_bits, ATTACK_LABELS, ATTACK_NONE, ATTACK_FORGERY,
    ATTACK_REPLAY, ATTACK_CHANNEL, MAX_MESSAGE_CHARS,
)
from rooms import RoomRegistry  # noqa: F401  (re-exported for room_server)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "qds_sessions.db")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
sock = Sock(app)

REGISTRY = RoomRegistry()


@app.after_request
def no_store(response):
    """
    Stop browsers from caching the phone pages and CSS.

    Without these headers, browsers cache the HTML/JS aggressively and keep
    serving a stale attacker.html after the page changes -- which repeatedly
    looked like "the replacement text box is broken" when the code was actually
    correct and only the cached copy was old. During a live demo that failure
    mode is expensive: the UI appears to lack features that exist.

    no-store on HTML/CSS only. API responses are small and benefit from being
    revalidated, and the session database is read fresh on every poll anyway.
    """
    if response.mimetype in ("text/html", "text/css", "application/javascript"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            code           TEXT PRIMARY KEY,
            message        TEXT NOT NULL,
            original_bits  TEXT NOT NULL,
            created_utc    TEXT NOT NULL,
            shots          INTEGER NOT NULL DEFAULT 256,
            attack         TEXT,
            attack_desc    TEXT,
            attacked_bits  TEXT,
            received_text  TEXT,
            received_bits  TEXT,
            verdict        TEXT,
            witness_json   TEXT,
            corrupted      INTEGER,
            total_bits     INTEGER,
            error_fraction REAL
        )
    """)
    # Additive migration. Databases created before the signature layer have no
    # witness_json column, and CREATE TABLE IF NOT EXISTS will not add one to an
    # existing table -- so the schema check has to be explicit.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "witness_json" not in cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN witness_json TEXT")
        print("Database migrated: added witness_json column.")
    conn.commit()
    conn.close()


def new_code() -> str:
    return "QCTD-" + "".join(random.choice(string.digits) for _ in range(4))


def _load_witness(row):
    """Decode the stored signature-layer result, tolerating old rows."""
    raw = None
    try:
        raw = row["witness_json"]
    except (IndexError, KeyError):
        return None
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return None


def row_to_session(row):
    return {
        "code": row["code"],
        "message": row["message"],
        "original_bits": [int(b) for b in row["original_bits"]],
        "created_utc": row["created_utc"],
        "shots": row["shots"],
        "attack": row["attack"],
        "attack_description": row["attack_desc"],
        "attacked_bits": [int(b) for b in (row["attacked_bits"] or "").split(",") if b != ""],
        "received_text": row["received_text"],
        "received_bits": [int(b) for b in (row["received_bits"] or "").split(",")] if row["received_bits"] else None,
        # These drive the victim's verdict badge and the per-bit table, so they
        # must be present even when no attack has run yet.
        "verdict": row["verdict"] or "AWAITING ATTACK",
        # Signature-layer finding, persisted with the attack so the dashboard
        # and email can report whether the quantum witness accepted the
        # signature and whether context binding caught a replay.
        "witness": _load_witness(row),
        "corrupted": row["corrupted"],
        "total_bits": row["total_bits"] or len(row["original_bits"]),
        "error_fraction": row["error_fraction"],
        "verification": None,
    }


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.route("/api/session", methods=["POST"])
def create_session():
    """Create a session from a message. Returns the shareable code."""
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    shots = int(data.get("shots") or 256)
    shots = max(64, min(shots, 512))

    try:
        bits = text_to_bits(message)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    code = new_code()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO sessions (code, message, original_bits, created_utc, shots) "
            "VALUES (?,?,?,?,?)",
            (code, message, "".join(str(b) for b in bits),
             datetime.now(timezone.utc).isoformat(), shots),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "ok": True, "code": code, "message": message,
        "total_bits": len(bits), "qubits": len(bits) * 3,
    })


@app.route("/api/session/<code>", methods=["GET"])
def get_session(code):
    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE code = ?", (code.upper(),)).fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "Session not found"}), 404
    return jsonify({"ok": True, "session": row_to_session(row)})


@app.route("/api/prior_sessions", methods=["GET"])
def prior_sessions():
    """
    Recent sessions that can be replayed.

    Replay means re-presenting a GENUINE signature from an EARLIER session, so
    the attacker needs to pick which one. Only sessions that already carry a
    transmitted result are listed, since replaying a session that never
    completed would not be replaying anything.
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT code, message, created_utc FROM sessions "
        "WHERE attack IS NOT NULL AND received_text IS NOT NULL "
        "ORDER BY created_utc DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return jsonify({"ok": True, "sessions": [dict(r) for r in rows]})


@app.route("/api/suggest_bits", methods=["POST"])
def suggest_bits():
    """
    Bit positions whose inversion produces legible damage.

    The attacker console calls this so a forgery shows visible corruption
    rather than one character out of twenty-four shifting by an alphabet step.
    Returns the positions alongside the resulting text, so the choice is
    visible before committing rather than discovered afterwards.
    """
    from message_layer import suggest_target_bits, apply_attack, bits_to_text

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    count = int(data.get("count") or 4)

    # The console sends a message id, not the plaintext. During transit the
    # plaintext is deliberately withheld from every client -- including the
    # attacker -- so the server resolves it here. Accepting a client-supplied
    # `text` as a fallback is fine for the local single-shot pages, which do
    # have the message in hand.
    mid = data.get("message_id")
    if not text and mid:
        import room_server
        for code in room_server.REGISTRY.list_rooms():
            room = room_server.REGISTRY.get(code)
            if room is None:
                continue
            msg = room.get(mid)
            if msg is not None:
                text = msg.get("text") or ""
                break

    try:
        bits = text_to_bits(text)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    positions = suggest_target_bits(text, count=count)
    out = apply_attack(ATTACK_FORGERY, bits, seed=1, target_bits=positions)

    return jsonify({
        "ok": True,
        "positions": positions,
        "original_text": text,
        "result_text": bits_to_text(out["bits"]),
        "touched": out["touched"],
    })


@app.route("/api/bit_diff", methods=["POST"])
def bit_diff():
    """
    Preview how many bits an attacker-supplied replacement would change.

    Used by the attacker page's live preview, so the person injecting can see
    WHY their substitution will be detected instead of guessing. Runs no
    simulation -- it is a plain comparison of the two bit patterns.
    """
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").upper()
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"ok": False, "error": "No replacement text supplied."}), 400

    conn = get_db()
    row = conn.execute(
        "SELECT original_bits FROM sessions WHERE code = ?", (code,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "Session not found"}), 404

    try:
        replacement = text_to_bits(text)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    original = [int(b) for b in row["original_bits"]]
    n = min(len(original), len(replacement))
    differing = sum(1 for i in range(n) if original[i] != replacement[i])
    # Length changes count too: a longer or shorter message alters the whole
    # tail even where the leading bits agree.
    differing += abs(len(original) - len(replacement))

    total = max(len(original), len(replacement))
    caught = differing > 0

    return jsonify({
        "ok": True,
        "total_bits": total,
        "differing_bits": differing,
        "would_be_caught": "DETECTED" if caught else "UNDETECTED",
        "error_rate": differing / total if total else 0.0,
    })


@app.route("/api/run_attack", methods=["POST"])
def run_attack():
    """
    Create a session and inject an attack in one call.

    The dashboard's Live Attack tab uses this so an attack can be run from the
    app itself, without needing the second phone. It is the same code path the
    phone demo uses -- identical simulation, identical detection -- so a result
    produced here is indistinguishable from one produced on the handset.
    """
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "TRANSFER $5000").strip()
    attack = data.get("attack") or ATTACK_NONE
    if attack == "honest":
        attack = ATTACK_NONE

    shots = int(data.get("shots") or 96)
    shots = max(64, min(shots, 512))

    try:
        bits = text_to_bits(message)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    targets = data.get("target_bits")
    if isinstance(targets, str):
        try:
            targets = [int(x) for x in targets.split(",") if x.strip()]
        except ValueError:
            targets = None
    elif not isinstance(targets, list):
        targets = None

    code = new_code()
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO sessions (code, message, original_bits, created_utc, shots) "
            "VALUES (?,?,?,?,?)",
            (code, message, "".join(str(b) for b in bits),
             datetime.now(timezone.utc).isoformat(), shots),
        )
        conn.commit()
    finally:
        conn.close()

    result = transmit_message(
        message, attack=attack, seed=random.randint(1, 10 ** 9),
        target_bits=targets, substitute=data.get("substitute"),
        shots=shots, session_id=code,
        issued_utc=datetime.now(timezone.utc).isoformat(),
    )
    v = result["verification"]
    witness = result.get("witness")

    conn = get_db()
    try:
        conn.execute(
            """UPDATE sessions SET attack=?, attack_desc=?, attacked_bits=?,
               received_text=?, received_bits=?, verdict=?, witness_json=?,
               corrupted=?, total_bits=?, error_fraction=? WHERE code=?""",
            (
                attack, result["attack_description"],
                ",".join(str(b) for b in result["attacked_bits"]),
                result["received_text"],
                "".join(str(b) for b in result["received_bits"]),
                v["status"],
                json.dumps(witness) if witness else None,
                v["corrupted_count"], v["total_bits"], v["error_fraction"], code,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "ok": True,
        "code": code,
        "message": message,
        "received_text": result["received_text"],
        "attack": attack,
        "attack_description": result["attack_description"],
        "verdict": v["status"],
        "corrupted_count": v["corrupted_count"],
        "total_bits": v["total_bits"],
        "corrupted_indices": v["corrupted_indices"],
        "signature_verdict": (witness or {}).get("verdict"),
        "context_verdict": (witness or {}).get("context_verdict"),
        "witness_passed": (witness or {}).get("witness_passed"),
    })


@app.route("/api/attack", methods=["POST"])
def inject_attack():
    """Execute an attack against a session. Runs the real quantum simulation."""
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").upper()
    attack = data.get("attack") or ATTACK_NONE
    # The API accepts "honest" as a synonym for "none"; normalize here so the
    # message layer only ever sees one spelling.
    if attack == "honest":
        attack = ATTACK_NONE

    targets = data.get("target_bits")
    if isinstance(targets, str):
        try:
            targets = [int(x) for x in targets.split(",") if x.strip()]
        except ValueError:
            targets = None
    elif not isinstance(targets, list):
        targets = None

    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE code = ?", (code,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Session not found"}), 404

    # A genuine replay re-sends an earlier session's ACTUAL signed bits and
    # its stored issue time. The signature layer hands those to the verifier,
    # so the quantum witness PASSES (it really is authentic) and the context
    # binding is what objects, because the transcript is stale. Without this
    # the path falls back to substituting text, which is forgery wearing a
    # replay label.
    replay_bits = None
    replay_session_id = None
    replay_issued = None
    replay_code = (data.get("replay_code") or "").strip().upper()
    if attack == "replay" and replay_code:
        prior = conn.execute(
            "SELECT original_bits, created_utc FROM sessions WHERE code = ?",
            (replay_code,),
        ).fetchone()
        if not prior:
            conn.close()
            return jsonify({"ok": False,
                            "error": f"Prior session {replay_code} not found."}), 404
        prior_bits = [int(b) for b in (prior["original_bits"] or "")]
        if not prior_bits:
            conn.close()
            return jsonify({"ok": False,
                            "error": f"Prior session {replay_code} has no stored "
                                     "bits to replay."}), 404
        replay_bits = prior_bits
        replay_session_id = replay_code
        replay_issued = prior["created_utc"]

    try:
        result = transmit_message(
            row["message"],
            attack=attack,
            seed=random.randint(1, 10 ** 9),
            target_bits=targets,
            substitute=data.get("substitute"),
            shots=row["shots"],
            # Honest hardware noise adds extra flipped bits on top of the
            # attack. That is physically right but muddies a targeted demo, so
            # callers can switch it off to land the attack exactly where aimed.
            inject_noise=not bool(data.get("noise_free", False)),
            session_id=code,
            issued_utc=row["created_utc"],
            replay_bits=replay_bits,
            replay_session_id=replay_session_id,
            replay_issued_utc=replay_issued,
        )
        v = result["verification"]

        conn.execute(
            """UPDATE sessions SET attack=?, attack_desc=?, attacked_bits=?,
               received_text=?, received_bits=?, verdict=?, witness_json=?,
               corrupted=?, total_bits=?, error_fraction=? WHERE code=?""",
            (
                attack,
                result["attack_description"],
                ",".join(str(b) for b in result["attacked_bits"]),
                result["received_text"],
                "".join(str(b) for b in result["received_bits"]),
                v["status"],
                json.dumps(result.get("witness")) if result.get("witness") else None,
                v["corrupted_count"], v["total_bits"],
                v["error_fraction"], code,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    # Two different verdicts, deliberately kept separate:
    #   verdict  -- per-bit INTEGRITY, from message_layer.verify_message
    #   w.verdict -- AUTHENTICITY, from the signature layer
    # For a replay these disagree by design: the bits are close enough to look
    # suspicious, while the witness PASSES and only context binding objects.
    # Collapsing them into one field would hide the interesting part.
    witness = result.get("witness") or {}
    signature_verdict = witness.get("verdict")

    return jsonify({
        "ok": True,
        "received_text": result["received_text"],
        "attack_description": result["attack_description"],
        "attacked_bits": result["attacked_bits"],
        "verdict": v["status"],
        "signature_verdict": signature_verdict,
        "context_verdict": witness.get("context_verdict"),
        "witness_passed": witness.get("witness_passed"),
        "witness": result.get("witness"),
        "corrupted_count": v["corrupted_count"],
        "total_bits": v["total_bits"],
        "error_fraction": v["error_fraction"],
        "corrupted_indices": v["corrupted_indices"],
    })


@app.route("/api/latest", methods=["GET"])
def latest_session():
    """Most recently created session. Lets app.py pull the latest phone incident."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM sessions ORDER BY created_utc DESC LIMIT 1"
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "No sessions yet"}), 404
    return jsonify({"ok": True, "session": row_to_session(row)})


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html", attacks=ATTACK_LABELS,
                           max_chars=MAX_MESSAGE_CHARS)


@app.route("/victim")
def victim():
    return render_template("victim.html", max_chars=MAX_MESSAGE_CHARS)


@app.route("/attacker")
def attacker():
    return render_template("attacker.html", attacks=ATTACK_LABELS)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def lan_ip() -> str:
    """Best-effort LAN address phones should use (not localhost)."""
    from network import primary_address
    return primary_address()


if __name__ == "__main__":
    init_db()

    # The room lives in its own module so a fault in the realtime path cannot
    # take the single-shot pages down with it -- those remain the fallback if
    # the room misbehaves mid-demo.
    import room_server
    import sys as _sys

    room_server.register_room_routes(app, _sys.modules[__name__])
    room_server.register_socket_routes(app, sock, _sys.modules[__name__])
    room_server.start_scheduler(_sys.modules[__name__])

    from network import describe, candidate_addresses
    port = 5000
    print("=" * 66)
    print(" QDS DEMO SERVER")
    print("=" * 66)
    print(f" On this laptop : http://localhost:{port}")
    print()
    print(" On your phones, open whichever address matches how they connected:")
    print(describe(port))
    print()
    cands = candidate_addresses()
    if cands and cands[0][0].startswith("192.168.137."):
        print(" NOTE: a Windows hotspot was detected. If your phones joined THIS")
        print("       laptop's hotspot, use the 192.168.137.x address above --")
        print("       they cannot reach the Ethernet address on the venue network.")
        print()
    print(" Both devices must be on the SAME network as this laptop.")
    print(" If Windows asks about the firewall, choose ALLOW on PRIVATE networks,")
    print(" otherwise the phones will not be able to connect.")
    print()
    print(" Room      : /room      <- group chat, many participants + attackers")
    print(" Victim    : /victim    <- single-shot fallback")
    print(" Attacker  : /attacker  <- single-shot fallback")
    print("=" * 66)
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)