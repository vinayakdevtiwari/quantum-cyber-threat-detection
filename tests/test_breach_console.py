"""
Drive the private-chat breach the way the attacker console does, over a real
WebSocket, so the console's actual flow is exercised rather than assumed.

Not part of the normal suite: it needs a live server. Run with
    QDS_TEST_SERVER=http://127.0.0.1:5000 python -m pytest tests/test_breach_console.py
"""

import json
import os
import time
import uuid

import pytest

from simple_websocket import Client

BASE = os.environ.get("QDS_TEST_SERVER")
pytestmark = pytest.mark.skipif(
    not BASE, reason="set QDS_TEST_SERVER to run the breach console test"
)
WS_BASE = BASE.replace("http://", "ws://").replace("https://", "wss://") if BASE else ""


class Client_:
    def __init__(self, name, code, attacker=False):
        self.id = uuid.uuid4().hex[:12]
        self.name = name
        self.frames = []
        self.ws = Client.connect(f"{WS_BASE}/ws/room")
        self.ws.send(json.dumps({
            "type": "join", "client_id": self.id, "name": name,
            "code": code, "transit": 30, "is_attacker": attacker,
        }))
        self.drain(until="joined", seconds=6)

    def send(self, o):
        self.ws.send(json.dumps(o))

    def drain(self, until=None, seconds=2.0):
        out, end = [], time.time() + seconds
        while time.time() < end:
            try:
                raw = self.ws.receive(timeout=0.2)
                if raw is None:
                    continue
                f = json.loads(raw)
            except OSError:
                break
            out.append(f)
            self.frames.append(f)
            if until and f.get("type") == until:
                break
        return out

    def await_frame(self, kind, seconds=25.0):
        self.drain(until=kind, seconds=seconds)
        for f in reversed(self.frames):
            if f.get("type") == kind:
                return f
        return None

    def state(self):
        for f in reversed(self.frames):
            if "state" in f:
                return f["state"]
        return None

    def close(self):
        try:
            self.ws.close()
        except OSError:
            pass


@pytest.fixture
def trio():
    code = "BR" + uuid.uuid4().hex[:5].upper()
    made = []

    def _make(n, attacker=False):
        c = Client_(n, code, attacker)
        made.append(c)
        return c

    yield _make
    for c in made:
        c.close()


def _delivered(state, text):
    return any(m["status"] == "delivered" and m["text"] == text
               for m in state["messages"])


def _open_dm(alice, peer):
    alice.send({"type": "open_dm", "peer_id": peer.id})
    f = alice.await_frame("dm_opened")
    assert f is not None, "DM never opened"
    return f["conversation"]["id"]


def test_attacker_sees_a_locked_dm_to_target(trio):
    """The console's victim list is built from locked DMs -- there must be one."""
    alice, bob, eve = trio("Alice"), trio("Bob"), trio("Eve", attacker=True)
    conv = _open_dm(alice, bob)

    # Eve joined before the DM existed, so the conversation only reaches her
    # snapshot once the room broadcasts after open_dm. Drain until it does.
    end = time.time() + 8
    rows = []
    while time.time() < end and not rows:
        eve.drain(seconds=0.5)
        st = eve.state() or {}
        rows = [c for c in st.get("conversations", []) if c["id"] == conv]

    assert rows, "the attacker cannot see the private chat exists"
    assert rows[0]["locked"] is True
    assert rows[0]["kind"] == "dm"


def test_console_guess_flow_is_refused(trio):
    """
    The exact path the console's GUESS button takes: pick a length, submit
    random bits, get a verdict. It must be refused.
    """
    alice, bob, eve = trio("Alice"), trio("Bob"), trio("Eve", attacker=True)
    conv = _open_dm(alice, bob)
    alice.send({"type": "send", "text": "PIN 9911", "shots": 64,
                "conversation_id": conv})
    assert bob.state() or True
    end = time.time() + 45
    while time.time() < end and not _delivered(bob.state() or {"messages": []}, "PIN 9911"):
        bob.drain(seconds=0.5)

    # What the console does: a length, and that many random bits.
    claimed = 96
    guess = [0, 1] * (claimed // 2)
    eve.send({"type": "dm_access", "conversation_id": conv,
              "candidate_bits": guess, "shots": 96})

    res = eve.await_frame("dm_access_result")
    assert res is not None, "the console never got a verdict"
    assert res["granted"] is False
    assert res["verdict"] == "ACCESS DENIED"
    # The console renders rows and a threshold; both must be present or the UI
    # draws an empty qubit strip and a zero-width bar.
    assert "rows" in res
    assert res.get("threshold") is not None


def test_console_short_length_is_refused_with_an_explanation(trio):
    """
    The console lets the operator claim any length. A wrong length must be
    refused, and the refusal must say why -- otherwise the operator cannot tell
    a wrong length from a rejected forgery.
    """
    alice, bob, eve = trio("Alice"), trio("Bob"), trio("Eve", attacker=True)
    conv = _open_dm(alice, bob)
    alice.send({"type": "send", "text": "PAYROLL 9000", "shots": 64,
                "conversation_id": conv})
    end = time.time() + 45
    while time.time() < end and not _delivered(bob.state() or {"messages": []}, "PAYROLL 9000"):
        bob.drain(seconds=0.5)

    eve.send({"type": "dm_access", "conversation_id": conv,
              "candidate_bits": [1, 0, 1], "shots": 64})
    res = eve.await_frame("dm_access_result")
    assert res is not None
    assert res["granted"] is False
    assert "witness is" in res["explanation"]


def test_correct_length_still_refused_for_a_guess(trio):
    """
    Knowing the length is not the secret. An attacker who claims the right
    number of bits but guesses their content must still be refused.
    """
    from message_layer import text_to_bits

    alice, bob, eve = trio("Alice"), trio("Bob"), trio("Eve", attacker=True)
    conv = _open_dm(alice, bob)
    alice.send({"type": "send", "text": "SALARY REVIEW Q3", "shots": 64,
                "conversation_id": conv})
    end = time.time() + 45
    while time.time() < end and not _delivered(bob.state() or {"messages": []}, "SALARY REVIEW Q3"):
        bob.drain(seconds=0.5)

    # Right length (the padded wire length is unknown, but try the plaintext
    # length and a few nearby), wrong content.
    n = len(text_to_bits("SALARY REVIEW Q3"))
    for claimed in (n, n * 8, n + 8):
        eve.send({"type": "dm_access", "conversation_id": conv,
                  "candidate_bits": [0, 1] * ((claimed // 2) + 1), "shots": 96})
        res = eve.await_frame("dm_access_result")
        assert res is not None
        assert res["granted"] is False, f"guess of {claimed} bits got in"


def test_denied_attempt_is_not_broadcast(trio):
    """
    A failed breach must stay between the attacker and the server. The console
    shows the verdict to Eve alone.
    """
    alice, bob, eve = trio("Alice"), trio("Bob"), trio("Eve", attacker=True)
    conv = _open_dm(alice, bob)
    alice.send({"type": "send", "text": "PIN 1234", "shots": 64,
                "conversation_id": conv})
    end = time.time() + 45
    while time.time() < end and not _delivered(bob.state() or {"messages": []}, "PIN 1234"):
        bob.drain(seconds=0.5)

    before_alice = len(alice.frames)
    eve.send({"type": "dm_access", "conversation_id": conv,
              "candidate_bits": [1] * 64, "shots": 96})
    assert eve.await_frame("dm_access_result") is not None

    alice.drain(seconds=1.5)
    bob.drain(seconds=1.0)
    assert "dm_access_result" not in json.dumps(alice.frames[before_alice:])
    assert "dm_access_result" not in json.dumps(bob.frames)