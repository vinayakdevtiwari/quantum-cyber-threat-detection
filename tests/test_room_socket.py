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
