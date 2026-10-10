"""
room_server.py

WebSocket transport and room REST routes for the group-chat demo.

Kept out of server.py so the single-shot flow and the room flow can be read
independently, and so a failure in one does not take down the other. The
single-shot pages remain the fallback if the room misbehaves mid-demo.

WHY WEBSOCKET RATHER THAN POLLING
---------------------------------
Polling a room every second looks alive but reads as dead: the countdown stutters,
attacks arrive a second late, and every participant's phone burns battery
polling. The transit window is only five seconds -- a one-second poll latency is
20% of the entire attack surface. A socket pushes state the moment it changes.

Threading model: Flask runs threaded, so each socket occupies one request thread
while it is open. That is fine for a room of a handful of phones and is far
simpler than an async server. The quantum work happens on worker threads so a
simulation never blocks a socket read.
"""

import json
import random
import threading
import time
from datetime import datetime, timezone

from flask import jsonify, render_template, request

from rooms import (
    RoomRegistry, deliver_message, STATUS_IN_TRANSIT, STATUS_DELIVERED,
    DEFAULT_TRANSIT_SECONDS, MAX_WORKERS, MAX_MESSAGE_CHARS, MIN_MESSAGE_CHARS,
)

# ---------------------------------------------------------------------------
# Registry and scheduler
# ---------------------------------------------------------------------------

REGISTRY = RoomRegistry()

_SCHEDULER_STOP = threading.Event()
_SCHEDULER_THREAD = None
_SEMAPHORE = threading.Semaphore(MAX_WORKERS)


def start_scheduler(app_module):
    """Start the transit dispatcher. Called once from server.py at startup."""
    global _SCHEDULER_THREAD
    if _SCHEDULER_THREAD and _SCHEDULER_THREAD.is_alive():
        return
    _SCHEDULER_STOP.clear()
    _SCHEDULER_THREAD = threading.Thread(
        target=_scheduler_loop, args=(app_module,),
        daemon=True, name="qds-transit",
    )
    _SCHEDULER_THREAD.start()


# ---------------------------------------------------------------------------
# Quantum transit for a room message
# ---------------------------------------------------------------------------

def _transit(room, msg, server):
    """
    Apply every logged attack in order, then run one real quantum transit.

    Sequential application is the point. Two attackers hitting one message
    produces a compound result -- Eve's bit flips, then Mallory's substitution
    over the top -- and the room can show that order rather than two rival
    explanations for the same bits.

    The quantum simulation runs ONCE, at the end, on the final bit pattern.
    That is both cheaper and more honest: what gets verified is exactly what
    would have travelled the channel.
    """
    from message_layer import (
        apply_attack, verify_message, bits_to_text, transit_bits,
        DEFAULT_NOISE_MODEL,
    )

    bits = list(msg["original_bits"])
    descriptions = []

    for entry in msg.get("attacks", []):
        kind = entry["attack"]
        if kind == "none" or kind == "honest":
            continue
        params = entry.get("params") or {}

        targets = params.get("target_bits")
        if isinstance(targets, str):
            targets = [int(t) for t in targets.split(",") if t.strip()]
        elif isinstance(targets, list):
            targets = [int(t) for t in targets]
        else:
            targets = None

        step = apply_attack(
            kind, bits,
            seed=random.randint(1, 10 ** 9),
            target_bits=targets,
            substitute=params.get("substitute"),
        )
        bits = [int(b) for b in step["bits"]]
        descriptions.append(step["description"])

    # The channel itself, via the same helper the single-shot path uses. Room
    # messages previously carried a separate copy of this loop, so a change to
    # the noise model had to be made twice and the two could drift apart.
    has_substitute = any(
        a.get("attack") in ("forgery_substitute", "replay")
        or bool(a.get("params", {}).get("substitute"))
        for a in msg.get("attacks", [])
    )
    inject_noise = not msg.get("noise_free", False) and not has_substitute

    transmitted = transit_bits(
        bits,
        shots=msg.get("shots", 96),
        noise_model=DEFAULT_NOISE_MODEL,
        inject_noise=inject_noise,
        seed=random.randint(1, 10 ** 9),
    )

    original = [int(b) for b in msg["original_bits"]]
    v = verify_message(original, transmitted)

    attacked_indices = [
        i for i in range(min(len(bits), len(original)))
        if bits[i] != original[i]
    ]

    # The signature-layer witness matters for two of these attacks, and they
    # behave completely differently:
    #   forgery_substitute -- the quantum witness REJECTS it, because the bits
    #                        on the wire were never part of the signed state.
    #   replay             -- the witness ACCEPTS it, because it really is a
    #                        genuine earlier signature. Only context binding
    #                        objects. Reporting both under one verdict would
    #                        hide the most interesting result in the demo.
    witness = None
    kinds = {a["attack"] for a in msg.get("attacks", [])}
    if kinds & {"forgery_substitute", "replay"}:
        try:
            witness = _run_witness(msg, bits, transmitted, kinds, server)
        except Exception as exc:  # noqa: BLE001
            print(f"[room] witness failed for {msg['id']}: {exc}")

    return {
        "ok": True,
        "received_bits": transmitted,
        "received_text": bits_to_text(transmitted),
        "attacked_bits": attacked_indices,
        "attack_description": (
            " ".join(descriptions) if descriptions
            else "No interference during transit. Message delivered intact."
        ),
        "corrupted_indices": v["corrupted_indices"],
        "corrupted_count": v["corrupted_count"],
        "total_bits": v["total_bits"],
        "error_fraction": v["error_fraction"],
        "verdict": v["status"],
        "witness": witness,
    }


def _run_witness(msg, bits, transmitted, kinds, server):
    """Invoke the signature layer for the substitution-family attacks."""
    from signature import sign_and_verify

    replay_prior = None
    sig_attack = "forgery"

    if "replay" in kinds:
        sig_attack = "replay"
        # Replay needs a genuine earlier session to re-send. Any prior session
        # will do -- the point is that the signature is REAL and the context
        # binding is what notices it is stale.
        prior = server.get_db().execute(
            "SELECT code, original_bits, created_utc FROM sessions "
            "WHERE received_text IS NOT NULL AND code LIKE 'QCTD-%' "
            "ORDER BY created_utc DESC LIMIT 1"
        ).fetchone()
        if prior:
            replay_prior = {
                "session_id": prior["code"],
                "message_bits": [int(b) for b in (prior["original_bits"] or "")],
                "issued_utc": prior["created_utc"],
            }

    raw = sign_and_verify(
        [int(b) for b in msg["original_bits"]],
        attack=sig_attack,
        seed=random.randint(1, 10 ** 9),
        n_signatures=2,
        shots=min(msg.get("shots", 96), 128),
        substitute=[int(b) for b in transmitted] if sig_attack == "forgery" else None,
        session_id=msg["id"][:12],
        replayed_from=replay_prior,
    )

    # Reduce to the same shape the single-shot path returns. The signature layer
    # nests the context result, and the room UI reads a flat `context_verdict`
    # -- storing the raw dict here would silently leave that field blank in the
    # room, which is exactly where the replay story has to land.
    ctx = raw.get("context") or {}
    return {
        "verdict": raw.get("verdict"),
        "mismatches": raw.get("mismatches"),
        "total": raw.get("total"),
        "forgery_probability": raw.get("forgery_probability", 0.0),
        "presentation": raw.get("presentation", ""),
        "witness_passed": raw.get("witness_passed"),
        "context_verdict": ctx.get("verdict"),
        "context_expected": ctx.get("expected"),
        "context_presented": ctx.get("presented"),
        "replayed_from": raw.get("replayed_from"),
        "note": raw.get("note"),
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _persist(server, msg, result):
    """
    Archive the delivered message into `sessions`.

    This is the bridge that makes the room feed the SOC dashboard and the
    emailed incident report with no extra wiring: the analytics side already
    reads `sessions`, so writing here is enough.

    A message hit by several attackers becomes one row describing the compound
    attack and naming everyone involved, rather than several rows that each
    claim to be the whole story.
    """
    if not result or not result.get("ok"):
        return

    code = "RM-" + msg["id"][:6].upper()
    attacks = msg.get("attacks", [])
    names = [a["attacker"] for a in attacks]

    if len(names) > 1:
        desc = (f"{result['attack_description']} "
                f"({len(names)} attackers acted in transit: {', '.join(names)}).")
        attack_kind = "+".join(dict.fromkeys(a["attack"] for a in attacks))
    elif names:
        desc = f"{result['attack_description']} Attacker: {names[0]}."
        attack_kind = attacks[0]["attack"]
    else:
        desc = "No interference during transit. Message delivered intact."
        attack_kind = "none"

    conn = server.get_db()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO sessions
               (code, message, original_bits, created_utc, shots, attack,
                attack_desc, attacked_bits, received_text, received_bits,
                verdict, witness_json, corrupted, total_bits, error_fraction)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                code,
                msg["text"],
                "".join(str(b) for b in msg["original_bits"]),
                datetime.now(timezone.utc).isoformat(),
                msg.get("shots", 96),
                attack_kind,
                desc,
                ",".join(str(b) for b in (result.get("attacked_bits") or [])),
                result.get("received_text"),
                "".join(str(b) for b in (result.get("received_bits") or [])),
                result.get("verdict"),
                json.dumps(result.get("witness")) if result.get("witness") else None,
                result.get("corrupted_count"),
                result.get("total_bits"),
                result.get("error_fraction"),
            ),
        )
        conn.commit()
    except Exception as exc:  # noqa: BLE001
        # Archiving is secondary to the live demo. If it fails the room result
        # is still correct on every screen; only the SOC record is missing.
        print(f"[room] could not archive {code}: {exc}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def _worker(server, room, msg):
    try:
        # A beat before the window opens so every client can render the message
        # before the countdown starts.
        time.sleep(0.4)
        room.open_window(msg)
        broadcast(room)

        time.sleep(msg.get("transit_seconds") or room.transit_seconds)

        had_attacks = bool(msg.get("attacks"))
        deliver_message(room, msg, lambda m: _transit(room, m, server))
        _persist(server, msg, msg.get("result"))

        # Reveal is a separate broadcast so clients can play it as a distinct
        # beat -- the room sees the bits change first, then learns who did it.
        if had_attacks:
            send_all(room, {"type": "reveal", "message_id": msg["id"]})
        broadcast(room)
    except Exception as exc:  # noqa: BLE001
        print(f"[room] worker failed for {msg.get('id')}: {exc}")
    finally:
        _SEMAPHORE.release()


def _scheduler_loop(server):
    """
    Dispatch queued messages to workers.

    One dispatcher thread plus a semaphore. The room is small -- a handful of
    people sending a few messages -- so a work queue library would be more
    machinery than the problem deserves.
    """
    while not _SCHEDULER_STOP.is_set():
        try:
            saturated = False
            for code in REGISTRY.list_rooms():
                room = REGISTRY.get(code)
                if room is None:
                    continue
                with room.lock:
                    pending = [m for m in room.messages if m["status"] == "queued"]
                for msg in pending:
                    if not _SEMAPHORE.acquire(blocking=False):
                        # All workers are busy. Skip this tick and retry -- the
                        # scheduler is a single long-lived thread, so bailing out
                        # here would strand every later message in `queued`
                        # forever.
                        saturated = True
                        break
                    threading.Thread(
                        target=_worker, args=(server, room, msg),
                        daemon=True, name="qds-transit-msg",
                    ).start()
                    break
                if saturated:
                    break
        except Exception as exc:  # noqa: BLE001
            print(f"[room] scheduler tick failed: {exc}")
        _SCHEDULER_STOP.wait(0.06)


# ---------------------------------------------------------------------------
# Broadcast
# ---------------------------------------------------------------------------

def broadcast(room):
    """Push a per-client snapshot to everyone in the room."""
    with room.lock:
        entries = list(room.clients.items())
    for cid, (client_id, send) in entries:
        try:
            send({"type": "state", "state": room.state(viewer_id=client_id)})
        except Exception:  # noqa: BLE001
            pass


def send_all(room, payload):
    with room.lock:
        entries = list(room.clients.values())
    for _client_id, send in entries:
        try:
            send(payload)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

def register_socket_routes(app, sock, server):
    """
    Attach the room socket to the Flask app.

    `sock` is a flask_sock instance; `server` is the server module itself, used
    for its database helpers. Passing the module rather than importing keeps a
    single definition of the schema.
    """

    @sock.route("/ws/room")
    def room_socket(ws):
        """
        One socket per participant.

        Inbound messages are small JSON commands; outbound are state snapshots.
        The socket reads in a loop on the request thread, so any slow receive
        from one phone would hold that thread only -- other phones are on
        their own threads.

        Writes are serialised per socket. State broadcasts originate on worker
        threads while errors and attack confirmations originate here, and two
        threads interleaving frames on one socket corrupts the stream in a way
        that presents as random UI glitches.
        """
        room = None
        pid = None
        write_lock = threading.Lock()

        def send(payload):
            with write_lock:
                ws.send(json.dumps(payload))

        try:
            while True:
                raw = ws.receive()
                if raw is None:
                    break
                try:
                    msg = json.loads(raw)
                except (TypeError, ValueError):
                    continue

                kind = msg.get("type")

                if kind == "join":
                    room = REGISTRY.get_or_create(
                        code=msg.get("code"),
                        name=msg.get("room_name"),
                        transit_seconds=msg.get("transit"),
                    )
                    part = room.join(
                        msg.get("name"), msg.get("is_attacker", False),
                        client_id=msg.get("client_id"),
                    )
                    pid = part.id

                    with room.lock:
                        room.clients[pid] = (pid, send)

                    send({
                        "type": "joined",
                        "room": room.code,
                        "room_name": room.name,
                        "you": {"id": pid, "name": part.name,
                                "is_attacker": part.is_attacker},
                        "transit_seconds": room.transit_seconds,
                        "state": room.state(viewer_id=pid),
                    })
                    broadcast(room)
                    continue

                if room is None or pid is None:
                    continue

                if kind == "send":
                    try:
                        room.add_message(
                            room.participants.get(pid),
                            msg.get("text"),
                            shots=int(msg.get("shots") or 96),
                            noise_free=bool(msg.get("noise_free")),
                        )
                        broadcast(room)
                    except (ValueError, AttributeError) as exc:
                        send({"type": "error", "error": str(exc)})
                    continue

                if kind == "attack":
                    part = room.participants.get(pid)
                    if part is None:
                        continue
                    entry, err = room.record_attack(
                        msg.get("message_id"), part,
                        msg.get("attack"), msg.get("params") or {},
                    )
                    if err:
                        send({"type": "error", "error": err,
                              "message_id": msg.get("message_id")})
                    else:
                        # Confirmed to the attacker only. Broadcasting it would
                        # tell the whole room an attack landed before delivery,
                        # which spoils the reveal.
                        send({"type": "attack_accepted",
                              "message_id": msg.get("message_id"),
                              "attack": entry["attack"]})
                    continue

                if kind == "role":
                    room.rename_role(pid, msg.get("is_attacker", False))
                    broadcast(room)
                    continue

                if kind == "ping":
                    send({"type": "pong", "t": time.time()})
                    continue

        except Exception as exc:  # noqa: BLE001
            # Normal on a phone locking its screen or dropping off the
            # hotspot. Never surface as a 500 -- the socket just closes.
            print(f"[room] socket closed: {exc}")
        finally:
            if room is not None and pid is not None:
                with room.lock:
                    room.clients.pop(pid, None)
                room.leave(pid)
                broadcast(room)


# ---------------------------------------------------------------------------
# REST (join, state, and a REST fallback for send/attack)
# ---------------------------------------------------------------------------

def register_room_routes(app, server):
    """REST endpoints. Socket handles realtime; these handle setup and recovery."""

    @app.route("/api/room/create", methods=["POST"])
    def room_create():
        data = request.get_json(silent=True) or {}
        room = REGISTRY.get_or_create(
            code=data.get("code"),
            name=data.get("name"),
            transit_seconds=data.get("transit"),
        )
        return jsonify({
            "ok": True,
            "code": room.code,
            "name": room.name,
            "transit_seconds": room.transit_seconds,
        })

    @app.route("/api/room/<code>", methods=["GET"])
    def room_state(code):
        room = REGISTRY.get(code)
        if room is None:
            return jsonify({"ok": False, "error": "Room not found"}), 404
        return jsonify({"ok": True, "room": room.state()})

    @app.route("/api/room/<code>/send", methods=["POST"])
    def room_send(code):
        """
        REST send.

        Exists because a WebSocket is not always available -- some corporate
        proxies and older mobile browsers refuse the upgrade. The room works
        without sockets, just with polling-level responsiveness.
        """
        data = request.get_json(silent=True) or {}
        room = REGISTRY.get(code)
        if room is None:
            return jsonify({"ok": False, "error": "Room not found"}), 404

        name = (data.get("name") or "anon").strip()[:24]
        client_id = data.get("client_id")
        part = room.participants.get(client_id) or room.join(
            name, bool(data.get("is_attacker")), client_id=client_id,
        )
        try:
            msg = room.add_message(
                part, data.get("text"),
                shots=int(data.get("shots") or 96),
                noise_free=bool(data.get("noise_free")),
            )
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400

        broadcast(room)
        return jsonify({"ok": True, "message_id": msg["id"],
                        "room": room.state(viewer_id=part.id)})

    @app.route("/api/room/<code>/attack", methods=["POST"])
    def room_attack(code):
        data = request.get_json(silent=True) or {}
        room = REGISTRY.get(code)
        if room is None:
            return jsonify({"ok": False, "error": "Room not found"}), 404

        client_id = data.get("client_id")
        part = room.participants.get(client_id)
        if part is None:
            return jsonify({"ok": False,
                            "error": "Join the room before attacking."}), 403

        entry, err = room.record_attack(
            data.get("message_id"), part,
            data.get("attack"), data.get("params") or {},
        )
        if err:
            return jsonify({"ok": False, "error": err}), 409
        return jsonify({"ok": True, "attack": entry["attack"],
                        "message_id": data.get("message_id")})

    @app.route("/api/room/<code>/role", methods=["POST"])
    def room_role(code):
        data = request.get_json(silent=True) or {}
        room = REGISTRY.get(code)
        if room is None:
            return jsonify({"ok": False, "error": "Room not found"}), 404
        part = room.rename_role(data.get("client_id"),
                                data.get("is_attacker", False))
        if part is None:
            return jsonify({"ok": False, "error": "Not in this room"}), 404
        broadcast(room)
        return jsonify({"ok": True, "is_attacker": part.is_attacker})

    @app.route("/room", methods=["GET"])
    def room_page():
        return render_template(
            "room.html",
            attacks=__import__("message_layer").ATTACK_LABELS,
            max_chars=MAX_MESSAGE_CHARS,
            min_chars=MIN_MESSAGE_CHARS,
            default_transit=DEFAULT_TRANSIT_SECONDS,
            rooms=REGISTRY.list_rooms(),
        )

    @app.route("/attack", methods=["GET"])
    def attack_page():
        """
        The operator console, at its own address.

        Separate from the room on purpose. A console embedded in the room would
        give the demonstration away before it began -- every participant would
        see the inject button. Opening it on a second phone also matches how an
        interception actually looks: the attacker is somewhere else entirely.
        """
        return render_template(
            "attack.html",
            attacks=__import__("message_layer").ATTACK_LABELS,
            max_chars=MAX_MESSAGE_CHARS,
            min_chars=MIN_MESSAGE_CHARS,
            code=request.args.get("c", ""),
        )
