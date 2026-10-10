"""
tests/test_room_socket.py

Two-client WebSocket tests for the room.

The room is the headline feature and it was the least covered: every earlier
test drove it over REST with a single client, while the browser UI speaks
WebSocket and expects live pushes. REST passing does not prove the socket
delivers, and the demo lives or dies on the socket.

These run against a live server, so they are skipped unless QDS_TEST_SERVER is
set:

    QDS_TEST_SERVER=http://127.0.0.1:5000 python -m pytest tests/test_room_socket.py

Note the host must be a literal IPv4 address. simple_websocket resolves
"localhost" to ::1 on this machine, and the Flask dev server listens on IPv4
only, so the connection is refused.
"""

import json
import os
import time
import uuid

import pytest

from message_layer import text_to_bits
from simple_websocket import Client

BASE = os.environ.get("QDS_TEST_SERVER")
pytestmark = pytest.mark.skipif(
    not BASE, reason="set QDS_TEST_SERVER to run socket tests (e.g. http://127.0.0.1:5000)"
)

WS_BASE = BASE.replace("http://", "ws://").replace("https://", "wss://") if BASE else ""


class Socket:
    """Minimal test client: connect, join, drain frames."""

    def __init__(self, name, room=None, attacker=False):
        self.id = uuid.uuid4().hex[:12]
        self.ws = Client.connect(f"{WS_BASE}/ws/room")
        self.send({
            "type": "join", "client_id": self.id, "name": name,
            "code": room or "", "transit": 30, "is_attacker": attacker,
        })
        self.frames = []
        self.joined = self.drain(until="joined", seconds=5)
        assert self.joined, f"{name} never received a joined frame"
        self.room = self.joined[0]["room"]

    def send(self, payload):
        self.ws.send(json.dumps(payload))

    def drain(self, until=None, seconds=2.0):
        """Collect frames until `until` arrives or the deadline passes."""
        out = []
        end = time.time() + seconds
        while time.time() < end:
            try:
                raw = self.ws.receive(timeout=0.2)
                if raw is None:
                    continue
                frame = json.loads(raw)
            except OSError:
                break
            out.append(frame)
            self.frames.append(frame)
            if until and frame.get("type") == until:
                break
        return out

    def state(self):
        """Most recent state frame seen."""
        for frame in reversed(self.frames):
            if "state" in frame:
                return frame["state"]
        return None

    def wait_for(self, predicate, seconds=20.0):
        """Wait for a state satisfying `predicate`. Returns it or None."""
        for frame in reversed(self.frames):
            if "state" in frame and predicate(frame["state"]):
                return frame["state"]
        end = time.time() + seconds
        while time.time() < end:
            for frame in self.drain(seconds=0.5):
                if "state" in frame and predicate(frame["state"]):
                    return frame["state"]
        return None

    def close(self):
        try:
            self.ws.close()
        except OSError:
            pass


@pytest.fixture
def room():
    code = "T" + uuid.uuid4().hex[:6].upper()
    made = []

    def _make(name, attacker=False):
        s = Socket(name, room=code, attacker=attacker)
        made.append(s)
        return s

    yield _make
    for s in made:
        s.close()


# --- two clients see each other -------------------------------------------

def test_second_client_is_pushed_to_the_first(room):
    """
    The first thing the room must do: tell someone already in the room that
    somebody else arrived. If this needs a poll or a refresh, the room is not
    live and the demo is not convincing.
    """
    alice = room("Alice")
    assert len(alice.state()["participants"]) == 1

    room("Bob")
    state = alice.wait_for(
        lambda s: len(s["participants"]) == 2, seconds=5
    )
    assert state is not None, "Alice was never told Bob joined"
    assert {p["name"] for p in state["participants"]} == {"Alice", "Bob"}


def test_sender_is_pushed_to_a_non_sender(room):
    alice = room("Alice")
    bob = room("Bob")

    alice.send({"type": "send", "text": "TRANSFER $5000", "shots": 64})

    state = bob.wait_for(
        lambda s: any(m["text"] == "TRANSFER $5000" or m["status"] == "queued"
                      for m in s["messages"]),
        seconds=6,
    )
    assert state is not None, "Bob never saw Alice's message"
    msg = state["messages"][-1]
    assert msg["sender"] == "Alice"


def test_mine_flag_distinguishes_senders(room):
    """
    Each client gets its own snapshot because `mine` differs per viewer. If the
    server cached one snapshot and fanned it out, both phones would render the
    same bubbles on the same side.
    """
    alice = room("Alice")
    bob = room("Bob")
    alice.send({"type": "send", "text": "FROM ALICE HERE", "shots": 64})
    bob.send({"type": "send", "text": "FROM BOB HERE", "shots": 64})

    def both(s):
        return len(s["messages"]) >= 2

    a_state = alice.wait_for(both, seconds=8)
    b_state = bob.wait_for(both, seconds=8)
    assert a_state and b_state

    a_mine = {m["sender"] for m in a_state["messages"] if m["mine"]}
    b_mine = {m["sender"] for m in b_state["messages"] if m["mine"]}
    assert "Alice" in a_mine
    assert "Bob" not in a_mine
    assert "Bob" in b_mine
    assert "Alice" not in b_mine


# --- the attack window -----------------------------------------------------

def test_plaintext_is_withheld_during_transit(room):
    """
    The leak that mattered. If the plaintext reached any client while the
    message was in flight, the attacker could read it off the wire instead of
    attacking anything.
    """
    alice = room("Alice")
    eve = room("Eve", attacker=True)

    alice.send({"type": "send", "text": "PAYROLL BONUS 777", "shots": 64})

    state = eve.wait_for(
        lambda s: any(m["status"] == "in_transit" for m in s["messages"]),
        seconds=20,
    )
    assert state is not None, "attacker never saw the message enter transit"
    inflight = [m for m in state["messages"] if m["status"] == "in_transit"]
    assert inflight, "message never reached in_transit"
    assert inflight[0]["text"] is None, "plaintext leaked during transit"
    assert "PAYROLL BONUS 777" not in json.dumps(state)


def test_attacker_injects_and_both_clients_see_the_result(room):
    alice = room("Alice")
    eve = room("Eve", attacker=True)

    alice.send({"type": "send", "text": "TRANSFER $5000", "shots": 64})
    state = eve.wait_for(
        lambda s: any(m["status"] == "in_transit" for m in s["messages"]),
        seconds=20,
    )
    assert state is not None
    mid = [m for m in state["messages"] if m["status"] == "in_transit"][0]["id"]

    eve.send({"type": "attack", "message_id": mid,
              "attack": "forgery_substitute",
              "params": {"substitute": "PAYROLL APPROVED"}})

    ack = eve.drain(until="attack_accepted", seconds=5)
    assert ack, "attack was not accepted"

    def delivered(s):
        return any(m["status"] == "delivered" for m in s["messages"])

    a_state = alice.wait_for(delivered, seconds=45)
    assert a_state is not None, "Alice never saw delivery"
    done = [m for m in a_state["messages"] if m["status"] == "delivered"][0]
    assert done["result"]["received_text"] == "PAYROLL APPROVED"
    assert done["result"]["verdict"] == "TAMPERED"
    # The attacker's name is only revealed after delivery.
    assert done["attacks"][0]["attacker"] == "Eve"


def test_non_attacker_is_refused(room):
    alice = room("Alice")
    bob = room("Bob")
    alice.send({"type": "send", "text": "TRANSFER $5000", "shots": 64})
    state = bob.wait_for(
        lambda s: any(m["status"] == "in_transit" for m in s["messages"]),
        seconds=20,
    )
    assert state is not None, "message never reached in_transit"
    mid = [m for m in state["messages"] if m["status"] == "in_transit"][0]["id"]

    bob.send({"type": "attack", "message_id": mid, "attack": "forgery",
              "params": {"target_bits": "0"}})

    err = bob.drain(until="error", seconds=5)
    assert err, "a non-attacker was not refused"
    assert "attacker" in err[0]["error"].lower()


def test_attacker_stays_hidden_until_reveal(room):
    alice = room("Alice")
    eve = room("Eve", attacker=True)

    state = alice.wait_for(
        lambda s: len(s["participants"]) == 2, seconds=5
    )
    assert state is not None
    assert state["revealed"] is False
    assert all(p["is_attacker"] is None for p in state["participants"])


# --- private conversations over the socket ---------------------------------

def _delivered(state, text):
    return any(m["status"] == "delivered" and m["text"] == text
               for m in state["messages"])


def _await(sock, frame_type, seconds=6.0):
    """
    Wait for one specific frame and return it.

    Socket.drain() returns EVERY frame it collected, not just the one it was
    waiting for, so indexing drain()[0] yields whatever state frame happened to
    arrive first. Selecting by type is the only reliable way to get a named
    frame out of it.
    """
    sock.drain(until=frame_type, seconds=seconds)
    for frame in reversed(sock.frames):
        if frame.get("type") == frame_type:
            return frame
    return None


def _open_dm(alice, peer_id):
    alice.send({"type": "open_dm", "peer_id": peer_id})
    opened = _await(alice, "dm_opened")
    assert opened is not None, "the DM was never opened"
    conv_id = opened["conversation"]["id"]
    assert conv_id.startswith("dm:")
    return conv_id


def test_dm_opens_and_carries_a_message(room):
    """The happy path: Alice opens a DM with Bob and sends into it."""
    alice = room("Alice")
    bob = room("Bob")

    conv_id = _open_dm(alice, bob.id)

    alice.send({"type": "send", "text": "PIN 4471", "shots": 64,
                "conversation_id": conv_id})

    state = bob.wait_for(lambda s: _delivered(s, "PIN 4471"), seconds=45)
    assert state is not None, "Bob never received the DM"
    msg = [m for m in state["messages"] if m["text"] == "PIN 4471"][0]
    assert msg["conversation_id"] == conv_id
    assert msg["conversation_kind"] == "dm"


def test_eve_cannot_see_dm_content_over_the_socket(room):
    """
    The headline privacy property, end to end over a real WebSocket.

    Eve is a room participant with an open socket. She must receive neither the
    DM plaintext nor the delivered result, in any state frame. Asserted against
    the serialised frame because that is what actually crosses the wire -- a
    leak in a field the UI happens not to render is still a leak.
    """
    alice = room("Alice")
    bob = room("Bob")
    eve = room("Eve", attacker=True)

    conv_id = _open_dm(alice, bob.id)

    alice.send({"type": "send", "text": "PAYROLL SECRET 9000", "shots": 64,
                "conversation_id": conv_id})

    # Let the message run all the way through transit.
    assert bob.wait_for(lambda s: _delivered(s, "PAYROLL SECRET 9000"),
                        seconds=45) is not None
    eve.drain(seconds=1.0)  # collect every frame Eve is sent

    assert eve.frames, "Eve received no frames at all"
    blob = json.dumps(eve.frames)
    assert "PAYROLL SECRET 9000" not in blob, (
        "DM plaintext leaked to the attacker over the socket")

    # Bob did get it, so this is a privacy boundary and not a delivery failure.
    assert _delivered(bob.state(), "PAYROLL SECRET 9000")


def test_dm_row_appears_locked_for_the_attacker(room):
    """Eve sees the conversation exists but cannot read it."""
    alice = room("Alice")
    bob = room("Bob")
    eve = room("Eve", attacker=True)

    conv_id = _open_dm(alice, bob.id)

    state = eve.wait_for(
        lambda s: any(c["id"] == conv_id for c in s["conversations"]), seconds=5
    )
    assert state is not None, "the attacker cannot even see the DM exists"
    row = next(c for c in state["conversations"] if c["id"] == conv_id)
    assert row["locked"] is True
    assert row["is_member"] is False


def test_outsider_cannot_send_into_a_dm(room):
    """
    Read access and write access are different things. Clearing the quantum
    gate grants reading; it must not let Eve post into someone else's chat.
    """
    alice = room("Alice")
    bob = room("Bob")
    eve = room("Eve", attacker=True)

    conv_id = _open_dm(alice, bob.id)

    eve.send({"type": "send", "text": "INJECTED", "shots": 64,
              "conversation_id": conv_id})

    err = _await(eve, "error")
    assert err is not None, "an outsider was allowed to send into a private chat"
    assert "private chat" in err["error"].lower()


def test_unknown_conversation_is_refused(room):
    """
    An unknown conversation id must not silently become the group. Falling back
    would publish a private message to the entire room while appearing to send
    it successfully.
    """
    alice = room("Alice")
    alice.send({"type": "send", "text": "HELLO", "shots": 64,
                "conversation_id": "dm:doesnot|exist"})
    err = _await(alice, "error")
    assert err is not None, "an unknown conversation id was accepted"
    assert "no such conversation" in err["error"].lower()


def test_gate_denies_a_guessing_attacker(room):
    """Eve tries to read the DM by presenting the plaintext she can see."""
    alice = room("Alice")
    bob = room("Bob")
    eve = room("Eve", attacker=True)

    conv_id = _open_dm(alice, bob.id)

    alice.send({"type": "send", "text": "PIN 9911", "shots": 64,
                "conversation_id": conv_id})
    assert bob.wait_for(lambda s: _delivered(s, "PIN 9911"), seconds=45) is not None

    # A guess: the attacker's best shot is the plaintext itself.
    eve.send({"type": "dm_access", "conversation_id": conv_id,
              "candidate_bits": text_to_bits("PIN 9911"), "shots": 64})

    res = _await(eve, "dm_access_result", seconds=25)
    assert res is not None, "the gate never answered"
    assert res["granted"] is False
    assert res["verdict"] == "ACCESS DENIED"
    assert res["match_rate"] < res["threshold"]


def test_access_verdict_is_not_broadcast_to_the_room(room):
    """
    A denied attempt is private. Broadcasting it would tell the room who is
    trying to break into a chat -- the one thing the chat is meant to keep
    quiet -- and would spoil the reveal by announcing the attempt before it
    has had a chance to succeed.
    """
    alice = room("Alice")
    bob = room("Bob")
    eve = room("Eve", attacker=True)

    conv_id = _open_dm(alice, bob.id)
    alice.send({"type": "send", "text": "PIN 9911", "shots": 64,
                "conversation_id": conv_id})
    assert bob.wait_for(lambda s: _delivered(s, "PIN 9911"), seconds=45) is not None

    eve.send({"type": "dm_access", "conversation_id": conv_id,
              "candidate_bits": text_to_bits("PIN 9911"), "shots": 64})
    assert _await(eve, "dm_access_result", seconds=25) is not None

    alice.drain(seconds=1.5)
    bob.drain(seconds=1.0)
    for other in (alice, bob):
        assert "dm_access_result" not in json.dumps(other.frames), (
            "an access attempt was broadcast to the room")
