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


# --- conversations: groups and private DMs ---------------------------------

def test_group_conversation_is_readable_by_everyone():
    room = _room()
    alice = room.join("Alice")
    eve = room.join("Eve", is_attacker=True)
    group = room.group_conversation()
    assert group.kind == rooms.CONV_GROUP
    assert group.is_member(alice.id)
    # An attacker is in the room, so the group is open to them by design.
    assert group.is_member(eve.id)


def test_dm_id_is_order_independent():
    """Whoever opens the chat first, it is the same conversation."""
    a, b = "p1", "p2"
    assert rooms.dm_conversation_id(a, b) == rooms.dm_conversation_id(b, a)


def test_opening_a_dm_is_idempotent_from_either_side():
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    first, err1 = room.open_dm(alice, bob.id)
    second, err2 = room.open_dm(bob, alice.id)
    assert err1 is None and err2 is None
    assert first is second
    # One DM. The group is created lazily on first use, so it is not counted
    # here -- asking for it is what brings it into existence.
    assert len(room.conversations) == 1


def test_dm_refuses_itself():
    """A chat with yourself is not a private chat."""
    room = _room()
    alice = room.join("Alice")
    assert room.open_dm(alice, alice.id)[1] is not None


def test_dm_with_someone_who_has_not_joined_yet_is_allowed():
    """
    A DM to an absent participant is still creatable, or a conversation could
    never exist before the other person arrived. The conversation simply has no
    readable second party until they join.
    """
    room = _room()
    alice = room.join("Alice")
    ghost = type("X", (), {"id": "not-here", "name": "Ghost"})()
    conv, err = room.open_dm(alice, ghost.id)
    assert err is None
    assert conv is not None
    # An absent participant has no display name, so the title must not leak
    # the raw participant id into the chat list.
    assert conv.title == "invited"

    # Once they join under that same participant id, the conversation picks up
    # their real name. Note the id has to match: room.join() mints a fresh id,
    # so a different id is a different person and correctly a different chat.
    late = room.join("Ghost", client_id=ghost.id)
    same, _ = room.open_dm(alice, late.id)
    assert same is conv
    assert conv.title == "Ghost"


def test_dm_members_can_read_it():
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    conv, _ = room.open_dm(alice, bob.id)
    assert room.can_read(conv, alice.id)
    assert room.can_read(conv, bob.id)


# --- the privacy boundary ---------------------------------------------------
#
# These are the tests that matter most. Everything else in this file could pass
# while DMs leak, because a leak is invisible in the UI -- the page renders
# fine and the content is simply sitting in the socket payload.

def test_eve_cannot_read_a_dm_plaintext():
    """
    An attacker in the room must not receive DM content in their snapshot.

    This is the property the whole private-chat feature rests on.
    """
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)

    conv, _ = room.open_dm(alice, bob.id)
    msg = room.add_message(alice, "PAYROLL SECRET 4471",
                           conversation=conv)
    msg["status"] = STATUS_DELIVERED
    msg["result"] = {
        "ok": True,
        "received_text": "PAYROLL SECRET 4471",
        "verdict": "VERIFIED",
    }

    eve_view = room.state(viewer_id=eve.id)

    blob = repr(eve_view)
    assert "PAYROLL SECRET 4471" not in blob, (
        "DM plaintext leaked into the attacker's state snapshot")

    # and the message is present but marked unreadable, so the console can
    # show a locked row rather than pretending the message never existed
    entry = next(m for m in eve_view["messages"] if m["id"] == msg["id"])
    assert entry["readable"] is False
    assert entry["text"] is None


def test_eve_cannot_read_received_text_from_the_result():
    """
    Regression guard for the subtler half of the leak.

    Stripping the message body is not sufficient: `result` carries
    received_text, so a snapshot that blanks `text` but still ships `result`
    hands over the entire conversation with the wrong field removed.
    """
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)

    conv, _ = room.open_dm(alice, bob.id)
    msg = room.add_message(alice, "PIN 9911", conversation=conv)
    msg["status"] = STATUS_DELIVERED
    msg["result"] = {"ok": True, "received_text": "PIN 9911", "verdict": "VERIFIED"}

    eve_view = room.state(viewer_id=eve.id)
    entry = next(m for m in eve_view["messages"] if m["id"] == msg["id"])
    assert entry["result"] is None
    assert "PIN 9911" not in repr(eve_view)


def test_members_still_see_their_own_dm():
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    conv, _ = room.open_dm(alice, bob.id)
    msg = room.add_message(alice, "PAYROLL SECRET 4471", conversation=conv)
    msg["status"] = STATUS_DELIVERED
    msg["result"] = {"ok": True, "received_text": "PAYROLL SECRET 4471",
                     "verdict": "VERIFIED"}

    for viewer in (alice, bob):
        view = room.state(viewer_id=viewer.id)
        entry = next(m for m in view["messages"] if m["id"] == msg["id"])
        assert entry["readable"] is True
        assert entry["text"] == "PAYROLL SECRET 4471"


def test_group_messages_are_still_visible_to_everyone():
    """The privacy rule must not break the existing group demo."""
    room = _room()
    alice = room.join("Alice")
    eve = room.join("Eve", is_attacker=True)
    msg = room.add_message(alice, "ROOM ANNOUNCEMENT")
    msg["status"] = STATUS_DELIVERED
    msg["result"] = {"ok": True, "received_text": "ROOM ANNOUNCEMENT",
                     "verdict": "VERIFIED"}

    view = room.state(viewer_id=eve.id)
    entry = next(m for m in view["messages"] if m["id"] == msg["id"])
    assert entry["readable"] is True
    assert entry["text"] == "ROOM ANNOUNCEMENT"


def test_master_seed_is_never_serialised():
    """
    The room's master secret must not appear in any snapshot. Only a short
    fingerprint is exposed so clients can tell rooms apart.
    """
    room = _room()
    alice = room.join("Alice")
    view = room.state(viewer_id=alice.id)
    assert room.master_seed not in repr(view)
    assert view["master_seed_fingerprint"] == room.master_seed[:8]
    assert len(view["master_seed_fingerprint"]) < 16


# --- the quantum gate, at the room layer -----------------------------------

def test_gate_refuses_an_attacker_who_is_guessing():
    """
    Eve joins the room and tries to read a DM she is not part of. She has no
    key, so the gate refuses -- and the refusal must not depend on whether she
    admits to being an attacker.
    """
    from signature import derive_conversation_key

    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)

    conv, _ = room.open_dm(alice, bob.id)
    msg = room.add_message(alice, "PAYROLL SECRET 4471", conversation=conv)
    msg["status"] = STATUS_DELIVERED
    msg["result"] = {"ok": True, "received_text": "PAYROLL SECRET 4471",
                     "verdict": "VERIFIED"}

    # Eve guesses: the plaintext, which is exactly what she would try first.
    guess = [int(b) for b in msg["original_bits"]]
    result, err = room.request_dm_access(eve, conv.id, guess, shots=64)

    assert err is None
    assert result["granted"] is False
    assert not room.can_read(conv, eve.id)


def test_gate_grants_a_holder_of_the_key():
    """
    Eve harvests the key from the room's seed and re-derives the wire bits.
    That is what possession of the key looks like, and it opens the chat.
    """
    from signature import derive_conversation_key, encrypt

    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)

    conv, _ = room.open_dm(alice, bob.id)
    msg = room.add_message(alice, "PAYROLL SECRET 4471", conversation=conv)
    msg["status"] = STATUS_DELIVERED

    key = derive_conversation_key(room.master_seed, conv.id,
                                  len(msg["original_bits"]))
    wire = encrypt(msg["original_bits"], key)

    result, err = room.request_dm_access(eve, conv.id, wire, shots=64)
    assert err is None
    assert result["granted"] is True
    assert room.can_read(conv, eve.id)


def test_grant_makes_the_dm_readable_in_state():
    """A granted attacker then sees the conversation, as the demo intends."""
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)

    conv, _ = room.open_dm(alice, bob.id)
    msg = room.add_message(alice, "PAYROLL SECRET 4471", conversation=conv)
    msg["status"] = STATUS_DELIVERED
    msg["result"] = {"ok": True, "received_text": "PAYROLL SECRET 4471",
                     "verdict": "VERIFIED"}

    room.grant_dm_access_for_test(conv.id, eve.id)
    view = room.state(viewer_id=eve.id)
    entry = next(m for m in view["messages"] if m["id"] == msg["id"])
    assert entry["readable"] is True
    assert entry["text"] == "PAYROLL SECRET 4471"


def test_a_member_does_not_need_the_gate():
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    conv, _ = room.open_dm(alice, bob.id)
    msg = room.add_message(alice, "hello bob", conversation=conv)
    msg["status"] = STATUS_DELIVERED
    result, err = room.request_dm_access(alice, conv.id, [], shots=64)
    assert err is None
    assert result["granted"] is True
    assert result["already_member"] is True


def test_gate_refuses_an_empty_conversation():
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)
    conv, _ = room.open_dm(alice, bob.id)
    result, err = room.request_dm_access(eve, conv.id, [1, 0, 1], shots=64)
    assert result is None
    assert err is not None


def test_dm_title_is_the_other_person_for_each_viewer():
    """
    A DM is one row in the list but two different conversations to read.

    Alice and Bob have the same private chat. Alice looks for "Bob" and Bob
    looks for "Alice". A single stored title can only be right for one of them,
    and whichever was wrong showed the reader their OWN name -- which reads as
    being in a chat with yourself.
    """
    room = _room()
    new = room.join("new")
    meow = room.join("meow")

    conv, err = room.open_dm(new, meow.id)
    assert err is None

    new_row = next(c for c in room.state(viewer_id=new.id)["conversations"]
                   if c["id"] == conv.id)
    meow_row = next(c for c in room.state(viewer_id=meow.id)["conversations"]
                    if c["id"] == conv.id)

    assert new_row["title"] == "meow", "the opener must see the other person"
    assert meow_row["title"] == "new", "the other side must see the opener"
    assert new_row["title"] != meow_row["title"]


def test_dm_title_follows_a_rename():
    """
    The name is resolved per viewer rather than stored at open time, so a
    participant who renames shows their new name immediately.
    """
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    conv, _ = room.open_dm(alice, bob.id)

    bob.name = "Bobby"
    row = next(c for c in room.state(viewer_id=alice.id)["conversations"]
               if c["id"] == conv.id)
    assert row["title"] == "Bobby"


def test_group_title_is_not_the_other_person():
    """The per-viewer title applies to DMs only. The group keeps the room name."""
    room = _room()
    room.name = "Team"
    alice = room.join("Alice")
    bob = room.join("Bob")
    group = room.group_conversation()

    for viewer in (alice, bob):
        row = next(c for c in room.state(viewer_id=viewer.id)["conversations"]
                   if c["id"] == group.id)
        assert row["title"] == "Team"


def test_dm_title_for_a_non_member_is_the_stored_title():
    """
    An outsider still sees a name so the locked row is renderable, but it is
    NOT resolved per viewer. To someone outside the chat there are two other
    people and no single "other", so resolving one would name whichever sorted
    first -- an arbitrary choice that shifts with the ids.

    Regression: an earlier version did exactly that, and the title differed
    between runs purely because of id ordering.
    """
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)
    conv, _ = room.open_dm(alice, bob.id)

    row = next(c for c in room.state(viewer_id=eve.id)["conversations"]
               if c["id"] == conv.id)
    assert row["locked"] is True
    assert row["is_member"] is False
    # the name the chat was opened with
    assert row["title"] == conv.title


def test_conversation_list_marks_locked_dms():
    """The console needs a 'locked' row to render, and it must not imply access."""
    room = _room()
    alice = room.join("Alice")
    bob = room.join("Bob")
    eve = room.join("Eve", is_attacker=True)
    conv, _ = room.open_dm(alice, bob.id)
    room.add_message(alice, "PAYROLL SECRET 4471", conversation=conv)

    view = room.state(viewer_id=eve.id)
    row = next(c for c in view["conversations"] if c["id"] == conv.id)
    assert row["kind"] == rooms.CONV_DM
    assert row["is_member"] is False
    assert row["locked"] is True

    member_view = room.state(viewer_id=alice.id)
    member_row = next(c for c in member_view["conversations"] if c["id"] == conv.id)
    assert member_row["locked"] is False


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
