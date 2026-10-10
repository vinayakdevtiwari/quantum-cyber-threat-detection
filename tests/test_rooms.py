"""
tests/test_rooms.py

Room behaviour that does not need Qiskit: lifecycle, membership, the transit
window, and the substitution/merge semantics that the room depends on.
"""

import pytest

import rooms
from rooms import (
    Room, STATUS_QUEUED, STATUS_IN_TRANSIT, STATUS_DELIVERED,
    MAX_MESSAGE_CHARS, MIN_MESSAGE_CHARS,
)


def _room(transit=5.0, **kw):
    return Room("TEST", "Test room", transit_seconds=transit, **kw)


def _sender(room, name="Alice"):
    return room.join(name)


# --- limits stay in step with the message layer -----------------------------

def test_limits_match_message_layer():
    """
    rooms.py re-declares these rather than importing them, to keep Qiskit off
    the request path. That makes drift possible, and they HAVE drifted: the
    room allowed 96 characters while the encoder allowed 24, so a 40-character
    room message was accepted and then rejected by the encoder.
    """
    from message_layer import (
        MAX_MESSAGE_CHARS as ML_MAX, MIN_MESSAGE_CHARS as ML_MIN,
    )
    assert MAX_MESSAGE_CHARS == ML_MAX
    assert MIN_MESSAGE_CHARS == ML_MIN


def test_noise_floor_brackets_the_measured_honest_rate():
    """
    message_layer.NOISE_FLOOR decides VERIFIED vs SUSPECT.
    attack_metrics.HONEST_MISMATCH_RATE is the measured mean of the same
    phenomenon. The floor must sit at or above that mean, or half of honest
    traffic reports SUSPECT and the demo's baseline looks compromised.

    The floor is allowed to be higher -- it is set to the p90 so the noisy tail
    of honest runs still verifies -- but never lower.
    """
    from message_layer import NOISE_FLOOR
    from attack_metrics import HONEST_MISMATCH_RATE

    assert NOISE_FLOOR >= HONEST_MISMATCH_RATE
    # And it must stay far below anything a real attack produces, or attacks
    # would verify clean.
    assert NOISE_FLOOR < 0.10


# --- membership -------------------------------------------------------------

def test_join_and_leave():
    room = _room()
    a = room.join("Alice")
    b = room.join("Bob")
    assert len(room.participants) == 2
    room.leave(a.id)
    assert a.id not in room.participants
    assert b.id in room.participants


def test_attacker_role_can_be_toggled_after_joining():
    room = _room()
    p = room.join("Eve")
    assert p.is_attacker is False
    room.rename_role(p.id, True)
    assert room.participants[p.id].is_attacker is True


def test_attackers_are_hidden_until_a_delivery():
    """
    The room's central reveal beat: participants look ordinary during transit
    and are labelled only once something has actually landed.
    """
    room = _room()
    room.join("Eve", is_attacker=True)
    room.join("Alice")

    assert all(p["is_attacker"] is None for p in room.state()["participants"])

    msg = room.add_message(_sender(room), "TRANSFER $5000")
    room.open_window(msg)
    assert all(p["is_attacker"] is None for p in room.state()["participants"])

    msg["status"] = STATUS_DELIVERED
    msg["result"] = {"ok": True}
    msg["attacks"] = [{"attacker": "Eve", "attack": "forgery", "effect": "x"}]

    revealed = {p["name"]: p["is_attacker"] for p in room.state()["participants"]}
    assert revealed["Eve"] is True
    assert revealed["Alice"] is False


# --- message lifecycle ------------------------------------------------------

def test_empty_and_overlong_messages_are_rejected_with_a_reason():
    room = _room()
    s = _sender(room)
    with pytest.raises(ValueError):
        room.add_message(s, "")
    with pytest.raises(ValueError):
        room.add_message(s, "   ")
    with pytest.raises(ValueError):
        room.add_message(s, "A" * (MAX_MESSAGE_CHARS + 1))


def test_short_messages_are_accepted():
    """The room must not impose a lower bound of its own -- see
    message_layer.MIN_MESSAGE_CHARS for why the earlier bound of eight was
    removed."""
    room = _room()
    s = _sender(room)
    for msg in ["hi", "ok", "yes"]:
        assert room.add_message(s, msg)["text"] == msg


def test_message_starts_queued_then_opens_a_window():
    room = _room(transit=5.0)
    msg = room.add_message(_sender(room), "TRANSFER $5000")
    assert msg["status"] == STATUS_QUEUED
    assert msg["text"] is not None  # server-side keeps it

    room.open_window(msg)
    assert msg["status"] == STATUS_IN_TRANSIT
    assert room.state()["messages"][0]["remaining"] is not None


def test_plaintext_is_withheld_from_clients_until_delivered():
    """
    Regression, and the most serious one in this module. `text` used to be sent
    unconditionally, which handed every client -- the attacker included -- the
    contents of any in-flight message. The attacker then had no need to
    intercept anything.
    """
    room = _room()
    msg = room.add_message(_sender(room), "PAYROLL BONUS 777")

    room.open_window(msg)
    assert room.state()["messages"][0]["text"] is None

    msg["status"] = STATUS_DELIVERED
    msg["result"] = {"ok": True}
    assert room.state()["messages"][0]["text"] == "PAYROLL BONUS 777"


# --- the attack window ------------------------------------------------------

def test_attacks_only_land_during_transit():
    room = _room()
    eve = room.join("Eve", is_attacker=True)
    msg = room.add_message(_sender(room), "TRANSFER $5000")

    entry, err = room.record_attack(msg["id"], eve, "forgery", {})
    assert entry is None and err  # still queued

    room.open_window(msg)
    entry, err = room.record_attack(msg["id"], eve, "forgery", {})
    assert entry is not None and err is None

    msg["status"] = STATUS_DELIVERED
    entry, err = room.record_attack(msg["id"], eve, "forgery", {})
    assert entry is None and "closed" in err.lower()


def test_non_attackers_cannot_inject():
    room = _room()
    bob = room.join("Bob")
    msg = room.add_message(_sender(room), "TRANSFER $5000")
    room.open_window(msg)

    entry, err = room.record_attack(msg["id"], bob, "forgery", {})
    assert entry is None and "attacker mode" in err.lower()


def test_several_attackers_stack_on_one_message():
    room = _room()
    eve = room.join("Eve", is_attacker=True)
    mallory = room.join("Mallory", is_attacker=True)
    msg = room.add_message(_sender(room), "TRANSFER $5000")
    room.open_window(msg)

    room.record_attack(msg["id"], eve, "forgery", {"target_bits": "40,41"})
    room.record_attack(msg["id"], mallory, "forgery_substitute",
                       {"substitute": "PAYROLL APPROVED"})

    assert len(msg["attacks"]) == 2
    # Order is preserved so the room can narrate the sequence.
    assert [a["attacker"] for a in msg["attacks"]] == ["Eve", "Mallory"]


# --- registry ---------------------------------------------------------------

def test_registry_reuses_an_existing_room():
    from rooms import RoomRegistry
    reg = RoomRegistry()
    a = reg.get_or_create(code="ABCD", name="One")
    b = reg.get_or_create(code="ABCD")
    assert a is b
    assert "ABCD" in reg.list_rooms()


def test_registry_sweeps_idle_rooms():
    import time as _time
    from rooms import RoomRegistry
    reg = RoomRegistry()
    room = reg.get_or_create(code="OLD1")
    room.touched_at = _time.time() - 10_000
    assert reg.sweep(ttl=3600) == 1
    assert reg.get("OLD1") is None


# --- substitution semantics the room relies on -----------------------------

def test_substitution_reaches_the_room_unchanged():
    """
    The truncation bug, at the room layer. "hi" plus "gay" used to deliver
    "ga" because the replacement was clipped to the victim's length.
    """
    from message_layer import text_to_bits, bits_to_text, apply_attack, ATTACK_SUBSTITUTE

    bits = text_to_bits("HI THERE")
    out = apply_attack(ATTACK_SUBSTITUTE, bits, seed=1, substitute="GAY")
    assert bits_to_text(out["bits"]) == "GAY"
