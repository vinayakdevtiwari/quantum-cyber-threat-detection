"""
rooms.py

Group-chat transport for the quantum digital signature demo.

WHY A ROOM
----------
The original demo was a two-page pairing: one phone was the victim, one was
the attacker. That is a clean demonstration of a single intercepted message,
but it does not look like a system anyone would deploy. It also cannot show the
thing that actually matters about interception -- that an attacker gets ONE
narrow window while a message is in flight, and everything else in the channel
is untouched.

A room makes the exposure explicit. One room, many participants, many senders.
Each message spends a fixed transit window in the channel, and that window is
the entire attack surface. Attackers act during it; when it closes the message
is verified and delivered to everyone.

MESSAGE LIFECYCLE
-----------------
    queued  ->  in_transit  ->  delivered

    queued       Created, waiting for the sender's bit encoding to finish.
    in_transit   Bits are travelling. Countdown running. ATTACK WINDOW OPEN.
    delivered    Verification complete. Result visible to the whole room.

Attacks are accepted only while `in_transit`. That restriction is the point of
the whole exercise: it is not that an attacker is powerful, it is that they are
brief, and the signature layer is what survives that window.

SEQUENCING ATTACKS
------------------
Several attackers may strike the same message. Their attacks are applied in
the order received and each one is logged with who did it, because "Eve flipped
bits, then Mallory swapped the text" is a story worth telling. Reconstructing
the order later would be impossible once the bits are overwritten.

STATE
-----
Room state is in memory and is deliberately not persisted. A room is a live
demonstration, not a record -- and the per-message forensic result IS
persisted, into the same `sessions` table the analytics dashboard reads, so the
SOC evidence survives even when the room does not.
"""

import random
import string
import threading
import time
import uuid

from signature import (
    new_master_seed, build_conversation_witness, gate_access,
    ACCESS_GRANTED,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TRANSIT_SECONDS = 5.0
MIN_TRANSIT_SECONDS = 1.0
MAX_TRANSIT_SECONDS = 15.0

STATUS_QUEUED = "queued"
STATUS_IN_TRANSIT = "in_transit"
STATUS_DELIVERED = "delivered"

# How long a finished room's state lingers in memory before being swept. Long
# enough that a phone reconnecting after a screen lock still sees the history;
# short enough that repeated demo runs do not accumulate.
ROOM_TTL_SECONDS = 3 * 60 * 60

# Both limits mirror message_layer. Re-declared rather than imported because
# message_layer pulls in Qiskit at module load, and this module sits on the
# room page's request path where that cost is unwanted.
#
# They used to disagree -- the room allowed 96 characters while the message
# layer allowed 24 -- so a room message of 40 characters was accepted by the
# room and then rejected by the encoder, surfacing as a failure after the
# sender had already hit send.
#
# tests/test_rooms.py asserts these stay in step with message_layer.
MAX_MESSAGE_CHARS = 64
MIN_MESSAGE_CHARS = 1

# The quantum simulation is genuinely expensive -- each bit is teleported and
# sampled. A room can have several messages in flight, so work is done on a
# worker thread rather than inline, or one participant's message would block
# every other participant's screen for seconds.
MAX_WORKERS = 4


def _clamp_transit(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return DEFAULT_TRANSIT_SECONDS
    return max(MIN_TRANSIT_SECONDS, min(MAX_TRANSIT_SECONDS, v))


def _room_code():
    """Short, unambiguous code. Excludes O/0/I/1 -- these get read aloud."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(alphabet) for _ in range(4))


class Participant:
    """One person in a room. Identity is a name, honestly labelled as such."""

    def __init__(self, name, pid=None, is_attacker=False):
        self.id = pid or uuid.uuid4().hex[:12]
        self.name = (name or "anon").strip()[:24] or "anon"
        self.is_attacker = bool(is_attacker)
        self.joined_at = time.time()

    def public(self, reveal_attackers=False):
        """
        What other clients are told about this participant.

        Attacker status is hidden until the reveal, by default. A demo where
        everyone can see who is an attacker is honest but flat; one where the
        reveal lands after delivery lets the room see the attack land before
        they learn who did it. The toggle exists because the second version
        needs explaining and the first sometimes does not.
        """
        d = {
            "id": self.id,
            "name": self.name,
            "is_attacker": self.is_attacker if reveal_attackers else None,
        }
        return d


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

CONV_GROUP = "group"
CONV_DM = "dm"


def dm_conversation_id(a, b):
    """
    Stable id for the private chat between two participants.

    Order-independent, so "dm:alice|bob" and "dm:bob|alice" are the same
    conversation no matter who opens it first. Sorting by participant id
    rather than display name means a rename cannot fork a conversation into
    two and orphan the history.
    """
    x, y = sorted([str(a), str(b)])
    return f"dm:{x}|{y}"


def group_conversation_id(room_code):
    """One group conversation per room. Its id is the room code itself."""
    return f"group:{room_code}"


class Conversation:
    """
    One chat inside a room: either the shared group or a private DM.

    A conversation is a view onto the room's message list, not a separate
    store. Messages still live in Room.messages and are tagged with a
    conversation id, so the existing transit scheduler, attack logging and
    delivery path keep working unchanged -- a DM is delivered by exactly the
    same code as a group message, differing only in who may read the result.

    WHY THE GROUP IS JUST ANOTHER CONVERSATION
    ------------------------------------------
    Making the group a conversation too means one privacy rule covers both,
    rather than a special case for DMs bolted onto group logic. It also means
    the attacker console can target "a message" without caring which kind it
    is, which is the whole premise of the demo.
    """

    def __init__(self, room, conv_id, kind, title, member_ids):
        self.room = room
        self.id = conv_id
        self.kind = kind
        self.title = title
        self.member_ids = set(member_ids)
        # Per-conversation quantum witness cache, keyed by message id. Built on
        # first need and never transmitted.
        self.witnesses = {}
        self.created_at = time.time()

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<Conversation {self.id} {self.kind} members={len(self.member_ids)}>"

    def is_member(self, participant_id):
        """
        May this participant read the plaintext?

        The group is readable by everyone in the room. A DM is readable only by
        its two members, or by someone who has been granted access by passing
        the quantum gate.
        """
        if self.kind == CONV_GROUP:
            return True
        return participant_id in self.member_ids

    def public(self, viewer_id=None, room=None):
        """Per-viewer summary. Never carries message content -- see Room.state.

        For a DM the title is the OTHER participant's name, not a single stored
        string. One conversation between Alice and Bob is one row in the list,
        but each of them is looking for the other person -- Alice wants to see
        "Bob" and Bob wants to see "Alice". A single title field can only be
        right for one of them, and whichever was wrong showed the reader their
        own name, which looks like the chat is with themselves.

        Resolving the name per viewer rather than storing it also means a
        participant who renames is reflected immediately, instead of the list
        keeping whichever name happened to be current when the chat was opened.

        Only a MEMBER gets the per-viewer treatment. To anyone outside the
        conversation there are two other people and no single "other", so
        picking whichever sorted first would name an arbitrary one and change
        with the ids. An outsider gets the stored title instead, which is the
        name the chat was opened with.
        """
        title = self.title
        if (self.kind == CONV_DM and room is not None
                and viewer_id is not None and self.is_member(viewer_id)):
            other_id = next(
                (m for m in sorted(self.member_ids) if m != viewer_id), None)
            other = room.participants.get(other_id) if other_id else None
            title = other.name if other is not None else self.title
        return {
            "id": self.id,
            "kind": self.kind,
            "title": title,
            "members": sorted(self.member_ids),
            "member_count": len(self.member_ids),
            "is_member": self.is_member(viewer_id),
        }


class Room:
    """A room: participants, messages, and the worker that drives delivery."""

    def __init__(self, code, name, transit_seconds=DEFAULT_TRANSIT_SECONDS,
                 reveal_attackers=False):
        self.code = code
        self.name = (name or code).strip()[:40] or code
        self.transit_seconds = _clamp_transit(transit_seconds)
        self.reveal_attackers = bool(reveal_attackers)
        self.created_at = time.time()
        self.touched_at = self.created_at

        self.participants = {}
        self.messages = []
        self.order = []
        self.conversations = {}

        # The room's master secret. Every conversation key derives from this,
        # so compromising it compromises every private chat in the room. It is
        # generated in memory and NEVER serialised into a state snapshot or
        # sent over the socket -- see Room.state and test_eve_cannot_read_dm.
        self.master_seed = new_master_seed()

        # Participants who have cleared the quantum gate for a DM, mapped
        # conv_id -> set of participant ids. Populated only by a successful
        # gate_access, never by a request.
        self.dm_grants = {}

        # One lock for the whole room. Contention is trivial -- a handful of
        # phones -- and it keeps message state transitions atomic. The quantum
        # work happens OUTSIDE this lock, so a long simulation never stalls a
        # second participant trying to send.
        self.lock = threading.RLock()

        # Sockets subscribed to this room, with the per-socket send lock.
        self.clients = {}

    # -- membership ---------------------------------------------------------

    def join(self, name, is_attacker=False, client_id=None):
        p = Participant(name, pid=client_id, is_attacker=is_attacker)
        with self.lock:
            self.participants[p.id] = p
            self.touched_at = time.time()
        return p

    def leave(self, pid):
        with self.lock:
            p = self.participants.pop(pid, None)
            self.touched_at = time.time()
        return p

    def rename_role(self, pid, is_attacker):
        """Toggle attacker mode after joining."""
        with self.lock:
            p = self.participants.get(pid)
            if p is None:
                return None
            p.is_attacker = bool(is_attacker)
            self.touched_at = time.time()
        return p

    # -- conversations ------------------------------------------------------

    def group_conversation(self):
        """The room's shared conversation. Created lazily so old rooms work."""
        cid = group_conversation_id(self.code)
        with self.lock:
            conv = self.conversations.get(cid)
            if conv is None:
                conv = Conversation(self, cid, CONV_GROUP, self.name,
                                    self.participants.keys())
                self.conversations[cid] = conv
                self.touched_at = time.time()
            return conv

    def open_dm(self, requester, other_id):
        """
        Open (or fetch) the private chat between two participants.

        Returns (conversation, error). The requester must be a participant of
        this room; the other party need not be -- a DM to someone who has not
        joined yet still has to be deliverable, otherwise the conversation
        could not exist before they arrive.
        """
        with self.lock:
            if requester is None or other_id is None:
                return None, "Both participants are required for a private chat."
            if requester.id not in self.participants:
                return None, "You are not in this room."
            if other_id == requester.id:
                return None, "A private chat needs two different people."

            other = self.participants.get(other_id)
            # Someone who has not joined yet has no display name, so fall back
            # to something readable rather than the raw participant id -- the
            # id is an implementation detail and shows up in the chat list.
            label = other.name if other else "invited"

            cid = dm_conversation_id(requester.id, other_id)
            conv = self.conversations.get(cid)
            if conv is None:
                conv = Conversation(self, cid, CONV_DM, label,
                                    [requester.id, other_id])
                self.conversations[cid] = conv
            elif other:
                # Refresh the title now that they have a real name. The id is
                # derived from participant ids, so renaming cannot fork the
                # conversation or orphan its history.
                conv.title = other.name

            self.touched_at = time.time()
            return conv, None

    def conversation(self, conv_id):
        with self.lock:
            conv = self.conversations.get(conv_id)
            if conv is not None:
                return conv
            # Unknown ids fall back to the group rather than erroring, so a
            # client that predates this field still renders something sane.
            return self.group_conversation()

    def can_read(self, conv, participant_id):
        """Membership, or a quantum grant. This is the only read path."""
        if conv is None:
            return False
        if conv.is_member(participant_id):
            return True
        with self.lock:
            return participant_id in self.dm_grants.get(conv.id, set())

    def request_dm_access(self, requester, conv_id, candidate_bits,
                          shots=96):
        """
        Run the quantum gate for a participant against a private conversation.

        `candidate_bits` is what the requester believes is on the wire. A
        holder of the conversation's key produces the true wire bits and is
        granted access; anyone guessing is refused.

        The room's master seed is never accepted as input and never leaves the
        server -- access is decided by the witness, which is the point.
        """
        with self.lock:
            conv = self.conversations.get(conv_id)
            if conv is None:
                return None, "No such private conversation."
            if requester is None or requester.id not in self.participants:
                return None, "You are not in this room."
            if conv.kind != CONV_DM:
                return None, "That conversation is not private."
            if conv.is_member(requester.id):
                # A member does not need the gate; saying so plainly avoids a
                # confusing denial for someone who is legitimately in the chat.
                return {
                    "granted": True,
                    "verdict": ACCESS_GRANTED,
                    "already_member": True,
                    "match_rate": 1.0,
                    "rows": [],
                    "total": 0,
                    "mismatches": 0,
                    "explanation": "You are a participant in this conversation.",
                }, None

        # Build the witness for the most recent message in this conversation.
        latest = None
        for m in reversed(self.messages):
            if m.get("conversation_id") == conv_id:
                latest = m
                break

        if latest is None:
            return None, "That conversation has no messages to verify against."

        from signature import derive_conversation_key, encrypt
        plain = [int(b) & 1 for b in latest["original_bits"]]
        key = derive_conversation_key(self.master_seed, conv_id, len(plain))
        built = build_conversation_witness(self.master_seed, conv_id, plain,
                                           shots=shots)
        result = gate_access(built["witness"], candidate_bits or [])

        if result["granted"]:
            with self.lock:
                self.dm_grants.setdefault(conv_id, set()).add(requester.id)
                self.touched_at = time.time()
        return result, None

    def grant_dm_access_for_test(self, conv_id, participant_id):
        """
        Record access without running the gate.

        For tests and for staging a demo where the operator decides which
        harvest Eve performs. Not reachable from the socket -- the wire path
        only ever calls request_dm_access.
        """
        with self.lock:
            self.dm_grants.setdefault(conv_id, set()).add(participant_id)
            self.touched_at = time.time()

    # -- messages -----------------------------------------------------------

    def add_message(self, sender, text, shots=96, noise_free=False,
                    conversation=None):
        from message_layer import text_to_bits

        text = (text or "").strip()
        if not text:
            raise ValueError("Message cannot be empty.")

        # text_to_bits is the single authority on both limits and raises with
        # the specific reason. Checking length here first only risks
        # disagreeing with it, which is exactly what happened when the room
        # allowed 96 characters and the encoder allowed 24.
        try:
            bits = text_to_bits(text)
        except ValueError as exc:
            raise ValueError(str(exc))

        # Default to the group so every existing caller -- the REST fallback,
        # the room socket, the tests -- keeps working unchanged. A DM is opted
        # into explicitly by passing its conversation.
        conv = conversation if conversation is not None else self.group_conversation()

        msg = {
            "id": uuid.uuid4().hex[:12],
            "sender": sender.name,
            "sender_id": sender.id,
            "conversation_id": conv.id,
            "conversation_kind": conv.kind,
            "text": text,
            "original_bits": bits,
            "shots": int(shots or 96),
            "noise_free": bool(noise_free),
            "status": STATUS_QUEUED,
            "created_at": time.time(),
            # Set when the transit window opens. Both wall-clock (for the
            # countdown the browser renders) and monotonic (for the scheduler,
            # which must not be moved by a clock adjustment mid-demo).
            "transit_ends_at": None,
            "transit_ends_mono": None,
            "attacks": [],
            "result": None,
        }
        with self.lock:
            self.messages.append(msg)
            self.order.append(msg["id"])
            self.touched_at = time.time()
        return msg

    def get(self, mid):
        with self.lock:
            for m in self.messages:
                if m["id"] == mid:
                    return m
        return None

    def record_attack(self, mid, attacker, attack, params):
        """
        Log an attack against an in-flight message.

        Rejected outside the transit window. That is the entire security
        argument of the demo in one conditional: the attacker had a window and
        the window closed.
        """
        with self.lock:
            msg = self.get(mid)
            if msg is None:
                return None, "Message not found in this room."
            if msg["status"] != STATUS_IN_TRANSIT:
                return None, (
                    "The transit window for this message has closed. Attacks only "
                    "land while the bits are in flight."
                )
            if not attacker.is_attacker:
                return None, "Enable attacker mode to inject an attack."

            entry = {
                "attacker": attacker.name,
                "attacker_id": attacker.id,
                "attack": attack,
                "params": params or {},
                "at": time.time(),
                # Filled in at delivery once the combined result is known.
                "effect": None,
            }
            msg["attacks"].append(entry)
            self.touched_at = time.time()
            return entry, None

    # -- serialisation ------------------------------------------------------

    def state(self, viewer_id=None, reveal=False):
        """
        Full room snapshot for one viewer.

        With `viewer_id`, each client gets its own copy because the `mine` flags
        differ per client -- so a snapshot cannot be shared across sockets.

        The reveal is automatic: as soon as any message has been delivered with
        an attack on it, the room stops concealing who the attackers are. That
        is the intended beat -- the room watches the bits change during transit,
        then learns who did it on delivery. An explicit `reveal=True` forces it
        earlier, which is useful for the fallback pages and for tests.
        """
        with self.lock:
            delivered_and_hit = any(
                m["status"] == STATUS_DELIVERED and m["attacks"]
                for m in self.messages
            )
            reveal_all = reveal or self.reveal_attackers or delivered_and_hit
            parts = [p.public(reveal_all) for p in self.participants.values()]

            msgs = []
            for m in self.messages:
                remaining = None
                if m["status"] == STATUS_IN_TRANSIT and m["transit_ends_at"]:
                    remaining = max(0.0, m["transit_ends_at"] - time.time())

                # Attacks are listed only after delivery, so the countdown is a
                # genuine countdown and nobody sees the roster of attackers
                # before the reveal. Names are withheld until then.
                shown_attacks = []
                if m["status"] == STATUS_DELIVERED:
                    for a in m["attacks"]:
                        shown_attacks.append({
                            "attacker": a["attacker"],
                            "attack": a["attack"],
                            "effect": a.get("effect"),
                        })

                # The plaintext is withheld until the message is delivered and
                # verified. Sending it during the window would hand every
                # client -- including the attacker -- the message contents
                # before the channel has delivered them, which defeats the
                # entire demonstration: an attacker would not need to intercept
                # anything, they could simply read the payload.
                delivered = (m["status"] == STATUS_DELIVERED
                             and bool(m["result"]))

                # ----------------------------------------------------------------
                # THE PRIVACY BOUNDARY
                # ----------------------------------------------------------------
                # A viewer who may not read this conversation gets no plaintext
                # AND no received text -- not a placeholder, not a truncated
                # form, nothing that could leak content by shape or length.
                #
                # `result` carries received_text, so stripping the message is
                # not enough on its own; the result has to be withheld too.
                # Shipping the one and forgetting the other is the obvious way
                # to get this wrong, and it would fail silently: the UI would
                # look fine and the leak would only be visible in the payload.
                readable = self.can_read(
                    self.conversations.get(m.get("conversation_id")), viewer_id)

                visible_text = (m["text"] if delivered else None) if readable else None
                visible_result = m["result"] if readable else None
                visible_attacks = shown_attacks if readable else []

                msgs.append({
                    "id": m["id"],
                    "sender": m["sender"],
                    "sender_id": m["sender_id"],
                    "conversation_id": m.get("conversation_id"),
                    "conversation_kind": m.get("conversation_kind", CONV_GROUP),
                    # None while in flight. The client renders a placeholder.
                    "text": visible_text,
                    # The UI shows this instead of the body when False, so a
                    # non-member learns the message exists without reading it.
                    "readable": readable,
                    "status": m["status"],
                    "created_at": m["created_at"],
                    "remaining": remaining,
                    "attacks": visible_attacks,
                    "attack_count": len(m["attacks"]),
                    "result": visible_result,
                    "mine": viewer_id is not None and m["sender_id"] == viewer_id,
                })

            # Conversation list, filtered to those this viewer can see at all.
            # A non-member still sees the DM EXISTS -- that is what makes the
            # attack console's "locked conversation" row meaningful -- but not
            # its contents.
            #
            # The title comes from Conversation.public() so it is resolved per
            # viewer. Reading conv.title directly here would give both sides of
            # a DM the same name, which is correct for at most one of them.
            convs = []
            for cid, conv in self.conversations.items():
                info = conv.public(viewer_id=viewer_id, room=self)
                info["granted"] = self.can_read(conv, viewer_id)
                info["locked"] = not info["granted"]
                convs.append(info)

            return {
                "code": self.code,
                "name": self.name,
                "transit_seconds": self.transit_seconds,
                "participants": parts,
                "messages": msgs,
                "conversations": convs,
                # Never the seed itself. Present only so a client can tell a
                # room apart from another with the same shape.
                "master_seed_fingerprint": self.master_seed[:8],
                "server_time": time.time(),
                "revealed": reveal_all,
            }

    def open_window(self, msg, seconds=None):
        """Open the attack window. Called by the scheduler once encoding is done."""
        with self.lock:
            secs = _clamp_transit(seconds if seconds is not None
                                  else self.transit_seconds)
            msg["status"] = STATUS_IN_TRANSIT
            msg["transit_ends_at"] = time.time() + secs
            msg["transit_ends_mono"] = time.monotonic() + secs
            msg["transit_seconds"] = secs
            self.touched_at = time.time()


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def deliver_message(room: Room, msg, run_transmit):
    """
    Run the quantum transit and verification for one message, then record the
    result.

    `run_transmit` is injected rather than imported so the quantum work can be
    stubbed in tests and so this module stays importable without pulling in
    Qiskit. It receives (bits, attacks, shots, noise_free) and returns the
    aggregate dict the UI renders.

    Called on a worker thread: the simulation takes seconds, and the room must
    stay responsive while it runs.
    """
    try:
        result = run_transmit(msg)
        with room.lock:
            msg["result"] = result
            msg["status"] = STATUS_DELIVERED
            msg["transit_ends_at"] = None
            msg["transit_ends_mono"] = None
            room.touched_at = time.time()

            # Attribute an effect to each logged attack, so the reveal can say
            # who did what rather than just that something happened.
            for a in msg["attacks"]:
                a["effect"] = _describe_attack_effect(a, result)
    except Exception as exc:  # noqa: BLE001
        with room.lock:
            msg["status"] = STATUS_DELIVERED
            msg["result"] = {
                "ok": False,
                "error": str(exc),
                "verdict": "TRANSIT FAILED",
            }
            room.touched_at = time.time()


def _describe_attack_effect(entry, result):
    """
    One line describing what an attack did.

    Deliberately describes the ATTACK, not the final bit pattern. With several
    attackers, a later one overwrites an earlier one's work, so reporting that
    the bits did not change would be technically true and completely
    misleading -- it makes the first attacker look as though they failed when
    they in fact succeeded and were then overwritten.
    """
    attack = entry["attack"]
    params = entry.get("params") or {}

    if attack == "forgery":
        bits = params.get("target_bits") or []
        if isinstance(bits, str):
            bits = [b for b in bits.split(",") if b.strip()]
        if bits:
            return f"inverted {len(bits)} bit(s) at {', '.join(str(b) for b in bits)}"
        return "inverted bits in the channel"
    if attack == "replay":
        src = params.get("replay_code")
        return (f"re-sent the genuine signed message from {src}" if src
                else "re-sent an earlier genuine message")
    if attack == "forgery_substitute":
        sub = params.get("substitute")
        return (f"replaced the text with {sub!r}" if sub
                else "replaced the message text")
    if attack == "impersonation":
        return "impersonated the sender"
    if attack == "channel_manipulation":
        return "manipulated the channel"
    corrupted = result.get("corrupted_count")
    return f"altered {corrupted} bit(s)" if corrupted is not None else "acted in transit"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class RoomRegistry:
    """In-memory room table with a sweep for rooms nobody has touched."""

    def __init__(self):
        self._rooms = {}
        self._lock = threading.RLock()

    def get_or_create(self, code=None, name=None, transit_seconds=None):
        code = (code or "").strip().upper()
        with self._lock:
            if code and code in self._rooms:
                room = self._rooms[code]
                if name:
                    room.name = name.strip()[:40] or room.name
                if transit_seconds is not None:
                    room.transit_seconds = _clamp_transit(transit_seconds)
                room.touched_at = time.time()
                return room

            # Retry on collision. Codes are short, so collisions are rare but
            # not negligible over a long demo.
            for _ in range(20):
                candidate = code or _room_code()
                if candidate not in self._rooms:
                    room = Room(candidate, name or f"Room {candidate}",
                                transit_seconds or DEFAULT_TRANSIT_SECONDS)
                    self._rooms[candidate] = room
                    return room
            raise RuntimeError("Could not allocate a room code.")

    def get(self, code):
        with self._lock:
            return self._rooms.get((code or "").strip().upper())

    def sweep(self, ttl=ROOM_TTL_SECONDS):
        """Drop rooms nobody has touched. Returns how many were removed."""
        cutoff = time.time() - ttl
        with self._lock:
            stale = [c for c, r in self._rooms.items() if r.touched_at < cutoff]
            for c in stale:
                self._rooms.pop(c, None)
            return len(stale)

    def list_rooms(self):
        with self._lock:
            return sorted(self._rooms.keys())

    def drop(self, code):
        with self._lock:
            return self._rooms.pop((code or "").strip().upper(), None) is not None
