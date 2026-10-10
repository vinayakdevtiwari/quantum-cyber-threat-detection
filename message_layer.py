"""
message_layer.py

Real message transport over the teleportation circuit, with per-bit
verification and visible attack injection.

WHY THIS EXISTS
---------------
The original pipeline protects a SINGLE qubit holding a single bit
(message_state is "0" or "1"). That makes the payload invisible: an attack
corrupts the bit, but there is no content to show as corrupted, and nothing to
localise. A mentor asking to see "the message get manipulated and the
receiver getting garbage" needs an actual message.

This module encodes a text message into a register of qubits, teleports each
one through the same 3-qubit protocol, applies a chosen attack to specific
qubits, and decodes what came out. The receiver compares received bits against
the signed original and reports exactly which positions differ.

WHAT THE DEMO SHOWS
-------------------
    SIGNED:     "TRANSFER $5000 TO ACCT 4471"
    RECEIVED:   "TRANSFER $9000 TO ACCT 4471"
                   ^
    bit 47: expected 0, received 1  -> FORGERY DETECTED

    SIGNED:     "AUTHORIZE OFFICER SINGH"
    RECEIVED:   "YUTHORIZE OFFICER SINGH"
    ...

SECURITY NOTE -- be precise about what this demonstrates
-------------------------------------------------------
Locating corrupted bits is a real integrity check, but it is NOT by itself a
signature. The receiver here is comparing against the ORIGINAL bits, which
presumes it already holds a trusted copy. That trusted copy is what a
quantum witness state provides (see signature.py in the wider project): a
forger cannot reproduce the correct bit pattern, because producing a state
that measures correctly in BOTH bases would require cloning it.

So the honest claim is:

  * This module: shows attack injection and per-bit integrity detection.
  * With a quantum witness added: makes forgery expensive rather than merely
    detectable, since the verifier's copy is the physical guarantee rather
    than something handed to them in advance.

Encoding note: ASCII, 8 bits per character, one qubit per bit. A 24-character
message is 192 qubits, which AerSimulator handles comfortably. Longer input is
rejected rather than silently truncated, because a silently shortened
security-relevant message is worse than a clear error.
"""

import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from simulator import build_noise_model

# Reuse the project's own noise models so this layer is consistent with the
# rest of the simulation rather than quietly running noiseless.
DEFAULT_NOISE_MODEL = build_noise_model(single_qubit_error=0.001, two_qubit_error=0.01)
DEGRADED_NOISE_MODEL = build_noise_model(single_qubit_error=0.02, two_qubit_error=0.09)

_sim = AerSimulator()

BITS_PER_CHAR = 8

# Longest message accepted.
#
# This was 24 for most of the project, on the belief that Aer would become
# impractical beyond it. Measured, that is not so: teleporting every bit costs
# roughly 1.5ms, so the whole transit is
#
#     24 chars (192 bits) -> 0.24s      60 chars (480 bits) -> 0.62s
#
# The circuits are three qubits each and are run independently, so cost is
# linear in message length and stays well inside a five-second transit window.
# 64 characters is enough for a full sentence, which matters for the demo:
# short strings give an attacker so few bits that the damage reads as a typo.
MAX_MESSAGE_CHARS = 64

# Shortest message worth attacking.
#
# No lower bound on message length. An earlier version required eight
# characters, on the reasoning that "hi" has too few bits for an attack to look
# like anything -- inverting one bit yields "hh", which reads as a typo. That
# was a reasonable worry but the wrong remedy: refusing the input is far worse
# than a small message whose attack lands quietly. It blocked ordinary use of
# the channel, and anyone typing "hi" or a short command was told the system
# did not work rather than being shown what it actually does.
#
# Short messages are now allowed. suggest_target_bits scales its count to the
# message, so a forgery on a short message still clears the noise floor, and a
# substitution still replaces it outright -- "hi" becomes "gay", not "ga".
#
# 1, not 0: text_to_bits already rejects empty and whitespace-only input.
MIN_MESSAGE_CHARS = 1

# Per-bit tolerance. A bit is flagged when it mismatches more than this
# fraction of the time. Hardware noise at the default model produces roughly
# 0.1-2% error, so 12% sits comfortably above honest noise and well below the
# ~50% an attack produces.
BIT_ERROR_TOLERANCE = 0.12

# Fraction of differing bits still considered consistent with an honest channel.
#
# Measured over 20 honest runs of a 512-bit message at the default noise model:
# mean 0.0199, median 0.0195, p90 0.0275, max 0.0332. The floor is set at the
# p90 rather than the mean so that roughly one honest run in ten still reports
# VERIFIED instead of SUSPECT -- a baseline that intermittently reads as
# compromised undercuts the entire demonstration. It remains far below any real
# attack, which lands above 10%.
#
# Matches HONEST_MISMATCH_RATE in attack_metrics.py, which is the same
# measurement; tests assert the two agree.
NOISE_FLOOR = 0.028

# Above this fraction of differing bits the message is treated as rewritten
# rather than corrupted in transit.
TAMPER_FRACTION = 0.25

# Slack allowed before SUSPECT, in differing bits.
#
# This started as a count floor to stop honest short traffic reading as
# compromised, then became a per-character fraction. Both were wrong. Scaling
# the slack with message length means a forgery that damages every character
# stays *inside* the allowance at small n and verifies clean -- measured, a
# two-bit forgery on "hi" was caught 0 times in 20. The attack is the thing
# this whole project exists to catch, so no amount of tidier honest traffic is
# worth weakening it.
#
# Reverted to a flat two bits: enough that a single honest noise flip on "hi"
# does not read as SUSPECT, small enough that any multi-character forgery on a
# short message still trips. Long messages were never affected -- 512 honest
# bits at 2% is about ten flips, comfortably inside the 2.8% NOISE_FLOOR, which
# is the fraction test doing that work.
MIN_TRANSPARENT_ERRORS = 2


# ---------------------------------------------------------------------------
def _merge_substitution(original: list, other: list) -> tuple:
    """
    Replace a message's bit pattern with an attacker's, padding or trimming
    deliberately rather than by accident.

    The earlier version copied `other` over `original` but kept the ORIGINAL
    length. That silently truncated any replacement longer than the victim's
    message: "hi" (16 bits) plus "gay" (24 bits) arrived as "ga", and "yes" plus
    "no" arrived as "nos" -- Alice's surviving tail. The attacker typed a
    sentence and got a different one, which reads as a broken attack rather than
    the attack it is.

    Here the attacker's message wins outright:
      - longer  -> padded with zeros so the whole text is delivered. The extra
                   trailing bytes decode as '.', which is how bits_to_text has
                   always rendered unprintable values.
      - shorter -> delivered exactly as typed, with nothing of Alice's left over.

    The padding is not a fudge. Changing the length of the message is precisely
    what an attacker who supplies their own content does, and the receiver's
    length check is part of what catches it.

    Returns (bits, padded_count).
    """
    if len(other) >= len(original):
        padded = list(other) + [0] * (len(other) - len(original))
        return padded, len(other) - len(original)
    return list(other), 0


# Encoding / decoding
# ---------------------------------------------------------------------------

def text_to_bits(message: str, enforce_min: bool = True) -> list:
    """
    Encode text as a list of 0/1 ints, 8 bits per character (ASCII).

    Raises ValueError on empty or over-long input rather than truncating,
    because a shortened message would misrepresent what was supposedly signed.

    enforce_min controls the MIN_MESSAGE_CHARS floor. It is on for the VICTIM's
    message -- that message has to be long enough for an attack to do visible
    damage -- but off for an attacker's REPLACEMENT text. There is no reason a
    payload Eve supplies has to be attackable; requiring eight characters of it
    only stops short replacements from working. When it is off, empty and
    over-long input are still rejected.
    """
    if not isinstance(message, str):
        raise ValueError("Message must be a string.")

    cleaned = message.strip()
    if not cleaned:
        raise ValueError("Message cannot be empty.")

    if enforce_min and len(cleaned) < MIN_MESSAGE_CHARS:
        raise ValueError(
            f"Message is {len(cleaned)} characters; the minimum is "
            f"{MIN_MESSAGE_CHARS}. A shorter message has too few bits for an "
            "attack to produce visible damage."
        )

    if len(cleaned) > MAX_MESSAGE_CHARS:
        raise ValueError(
            f"Message is {len(cleaned)} characters; the limit is {MAX_MESSAGE_CHARS}. "
            "Longer messages need more qubits and slow the simulation."
        )

    try:
        encoded = cleaned.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            "Message must contain ASCII characters only (letters, digits and "
            "common punctuation)."
        ) from exc

    bits = []
    for byte in encoded:
        for shift in range(BITS_PER_CHAR - 1, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_text(bits: list) -> str:
    """
    Decode a list of 0/1 ints back to text.

    Bytes that do not map to printable ASCII are rendered as '.', so a
    corrupted message is still legible as garbage rather than producing
    control characters that wreck the UI.

    Trailing NUL bytes are dropped rather than shown. Substitution padding uses
    zeros to carry an attacker's longer message past the victim's original
    length, and rendering those as a row of dots would read as damage when the
    message is in fact intact -- the padding is structure, not corruption.
    Interior NULs still render as '.', since those genuinely indicate damage.
    """
    if not bits:
        return ""

    out = []
    for i in range(0, len(bits) - BITS_PER_CHAR + 1, BITS_PER_CHAR):
        byte = 0
        for bit in bits[i:i + BITS_PER_CHAR]:
            byte = (byte << 1) | (int(bit) & 1)
        char = chr(byte)
        out.append(char if 32 <= byte < 127 else ".")

    # Trim trailing NUL padding. The '.' above has already hidden those bytes,
    # so they have to be identified from the raw byte values rather than from
    # the rendered string. Interior NULs are left as '.': those genuinely
    # indicate damage, while trailing ones are structure added by
    # _merge_substitution to carry a longer attack past the victim's length.
    text = "".join(out)
    end = len(text)
    while end > 0:
        start = (end - 1) * BITS_PER_CHAR
        byte = 0
        for bit in bits[start:start + BITS_PER_CHAR]:
            byte = (byte << 1) | (int(bit) & 1)
        if byte != 0:
            break
        end -= 1

    return text[:end] if end else text


# ---------------------------------------------------------------------------
# Quantum transport
# ---------------------------------------------------------------------------

def build_bit_circuit(bit: int, noise_model=None) -> QuantumCircuit:
    """
    Teleport a single message bit from Alice (q0/q1) to Bob (q2).

    This is the same protocol as simulator.build_teleportation_circuit,
    specialised to one bit and one qubit triple, so results stay consistent
    with the rest of the project.
    """
    qc = QuantumCircuit(3, 3)

    # Prepare the message qubit.
    if bit:
        qc.x(0)
    qc.barrier()

    # Entangle Alice's and Bob's halves.
    qc.h(1)
    qc.cx(1, 2)
    qc.barrier()

    # Bell measurement on the message + Alice's half.
    qc.cx(0, 1)
    qc.h(0)
    qc.measure([0, 1], [0, 1])
    qc.barrier()

    # Pauli correction conditioned on the measurement outcome.
    qc.cx(1, 2)
    qc.cz(0, 2)
    qc.measure(2, 2)

    return qc


def transmit_bit(bit: int, shots: int = 256, noise_model=DEFAULT_NOISE_MODEL) -> float:
    """
    Teleport one bit and return P(received == sent).

    Qiskit reports counts as c2 c1 c0, so Bob's qubit (clbit 2) is the
    LEFTMOST character. Reading the wrong end reports ~50% fidelity on a
    perfectly honest transfer.
    """
    qc = build_bit_circuit(bit, noise_model)
    job = _sim.run(qc, shots=shots, noise_model=noise_model)
    counts = job.result().get_counts()

    total = sum(counts.values())
    if total == 0:
        return 0.5

    # bitstring[0] is clbit 2 = Bob's teleported qubit.
    matches = sum(n for key, n in counts.items() if key[0] == str(int(bit) & 1))
    return matches / total


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------

ATTACK_NONE = "none"
# Some callers (the API surface, the signature module) spell the honest case
# "honest". Accept both so a client sending either does not get an
# "Unknown attack" 500 -- that mismatch previously made the honest path
# unusable through the phone backend.
ATTACK_HONEST = "honest"
ATTACK_FORGERY = "forgery"
ATTACK_IMPERSONATION = "impersonation"
ATTACK_REPLAY = "replay"
ATTACK_CHANNEL = "channel_manipulation"
# New: Eve submits her OWN message rather than corrupting Alice's. Per-bit
# integrity comparison cannot catch this, because her message is internally
# consistent -- signature.verify_witness() is what catches it.
ATTACK_SUBSTITUTE = "forgery_substitute"

ATTACK_LABELS = {
    ATTACK_NONE: "No attack (honest channel)",
    ATTACK_FORGERY: "Forgery (flip chosen bits)",
    ATTACK_IMPERSONATION: "Impersonation (phase error)",
    ATTACK_REPLAY: "Replay (re-send a prior valid signature)",
    ATTACK_CHANNEL: "Channel manipulation (random bits)",
    ATTACK_SUBSTITUTE: "Forgery - substitute (needs quantum witness)",
}


def suggest_target_bits(text: str, count: int = 4, spread: bool = True) -> list:
    """
    Pick bit positions whose inversion produces LEGIBLE damage.

    A random bit in a 192-bit message is usually the low bit of a letter, so
    flipping it turns 'A' into 'B' -- one character out of twenty-four changes
    and the damage is invisible at a glance. What reads as an interception is a
    character becoming a symbol, so this deliberately targets the high bits of
    each character: those map to the ASCII punctuation and control ranges.

    This is a demo affordance, not a claim about attacker capability. An
    attacker who can reach the channel can flip any bit they like; choosing
    well is about making the demonstration legible, and the mechanism is
    identical either way.

    `spread` spaces the picks across the message so the result reads as damage
    throughout rather than clustered in one word.

    The count is scaled to the message so it always clears NOISE_FLOOR. A fixed
    four-bit attack is 20% of a 160-bit message and comfortably detectable, but
    only 0.8% of a 512-bit one -- indistinguishable from hardware noise, so the
    verifier would report the tampered message as VERIFIED. Scaling keeps the
    demonstrated attack meaningful at every length.
    """
    try:
        bits = text_to_bits(text)
    except ValueError:
        return []

    total = len(bits)
    if total == 0:
        return []

    n_chars = total // BITS_PER_CHAR
    if n_chars == 0:
        return [0]

    # Enough flips to clear the noise floor with margin, but never more than
    # there are characters to damage. At 512 bits this is ~20 bits (3.9%); at
    # 160 it is ~7. Both read as interference rather than speckle.
    floor_bits = int(total * (NOISE_FLOOR * 2.2)) + 1
    count = max(int(count or 0), floor_bits)
    count = max(1, min(count, n_chars))

    # The two most significant bits of each character. Clearing these drops a
    # letter into the control/symbol range that bits_to_text renders as '.'.
    cands = [c * BITS_PER_CHAR for c in range(n_chars)]

    if spread and count < len(cands):
        step = len(cands) / count
        picked = [cands[int(i * step)] for i in range(count)]
    else:
        picked = cands[:count]

    return sorted(set(picked))


def apply_attack(attack: str, bits: list, seed=None,
                 target_bits=None, substitute: str = None,
                 replay_bits=None) -> dict:
    """
    Corrupt a message's bit pattern the way an on-path attacker would.

    The returned dict describes exactly what the attacker did, which the UI
    shows on BOTH screens -- the attacker sees their own action, the victim
    sees the damage. Being explicit about the mechanism is what makes the
    demo honest rather than theatrical.

    target_bits: bit indices to corrupt (forgery). None = pick one.
    substitute: replacement text for replay/forgery. None = a fixed alternate message.
    replay_bits: the EXACT bit pattern of a genuine earlier signature, when one
        is available. Supplying this is what makes replay a real replay rather
        than a text substitution: the bits are the ones that were actually
        signed and witnessed in that earlier session, not a re-encoding of its
        text. Falls back to `substitute` when absent.
    """
    rng = np.random.default_rng(seed)
    corrupted = list(bits)
    total = len(bits)
    description = ""
    touched = []

    if attack in (ATTACK_NONE, ATTACK_HONEST) or total == 0:
        return {"bits": corrupted, "description": "No attack applied.",
                "touched": [], "attack": ATTACK_NONE}

    if attack == ATTACK_FORGERY:
        # X errors: a targeted, surgical corruption of specific bits. This is
        # the demo's centrepiece because the resulting text change is legible
        # and traceable to exact bit positions.
        if target_bits:
            chosen = [b for b in target_bits if 0 <= b < total]
        else:
            chosen = [int(rng.integers(0, total))]
        if not chosen:
            chosen = [0]
        for b in chosen:
            corrupted[b] ^= 1
        touched = sorted(set(chosen))
        description = (f"Forgery: inverted {len(touched)} bit(s) at "
                       f"{', '.join(str(b) for b in touched)} (X error).")

    elif attack == ATTACK_IMPERSONATION:
        # A phase (Z) error on the entangled half. It leaves the Z-basis value
        # untouched and only reveals itself under a different measurement
        # basis, which is exactly why basis choice matters in QDS.
        count = max(1, total // 16)
        chosen = sorted(set(rng.choice(total, size=min(count, total),
                                       replace=False).tolist()))
        for b in chosen:
            corrupted[b] ^= 1
        touched = chosen
        description = (f"Impersonation: phase error disturbing {len(chosen)} "
                       f"bit(s) at {', '.join(str(b) for b in chosen[:8])}"
                       f"{'...' if len(chosen) > 8 else ''} (Z error).")

    elif attack == ATTACK_REPLAY:
        # A TRUE replay, not a forgery in disguise. Eve re-sends a genuine
        # message that was legitimately signed earlier, together with its own
        # genuine witness. The quantum checks therefore PASS -- the signature
        # is real. What fails is CONTEXT: the signature was bound to a
        # different session, and the transcript hash no longer matches.
        #
        # The earlier version simply swapped in arbitrary text, which is
        # forgery wearing a replay label. That misrepresented what the
        # protocol actually defends against.
        if replay_bits:
            # The genuine earlier signature, bit for bit. Not a re-encoding of
            # its text -- this is the exact pattern that was signed and whose
            # witness was stored, which is what makes the replay authentic.
            other = [int(b) & 1 for b in replay_bits]
            source = "a stored earlier session"
        else:
            text = substitute if substitute else replayable_prior_message(
                "".join(str(int(b) for b in bits_to_text(bits)))
            )
            # No silent fallback. Previously an unencodable replacement was
            # swapped for a fixed string, so an attacker who typed something
            # unusable was shown a successful injection while a different
            # message went on the wire -- the UI and the channel disagreed with
            # no indication of which was right.
            other = text_to_bits(text, enforce_min=False)
            source = "an earlier legitimate message"

        corrupted, _pad = _merge_substitution(bits, other)
        touched = []
        description = ("Replay: Eve re-sent a genuine, previously-signed message "
                       f"from {source}, together with its own witness. Every "
                       "quantum check PASSES -- the signature is authentic. It is "
                       "caught only because its context binding names an earlier "
                       "session, which the receiver detects as a stale transcript.")

    elif attack == ATTACK_CHANNEL:
        # Randomised multi-bit corruption: the "true garbage" case.
        count = max(1, total // 5)
        chosen = sorted(set(rng.choice(total, size=min(count, total),
                                       replace=False).tolist()))
        for b in chosen:
            corrupted[b] ^= 1
        touched = chosen
        description = (f"Channel manipulation: randomly corrupted {len(chosen)} "
                       f"bit(s) ({len(chosen)/total*100:.0f}% of the message).")

    elif attack == ATTACK_SUBSTITUTE:
        # Eve never tampers with Alice's message -- she presents her own.
        # Nothing is corrupted in transit, so any check that inspects only
        # transport integrity sees a perfectly consistent message. Detecting
        # this therefore depends on AUTHENTICITY (was this message actually
        # signed by Alice?), which the quantum witness provides and a
        # transport-level check does not.
        text = substitute if substitute else "PAYROLL $9000 SINGH"
        # Unencodable input raises rather than falling back to a fixed string.
        # A silent substitution here means the attacker is told the injection
        # worked while the room receives something they never typed.
        other = text_to_bits(text, enforce_min=False)
        corrupted, _pad = _merge_substitution(bits, other)
        touched = []
        description = ("Forgery by substitution: Eve presented her own message "
                       "rather than a corrupted copy of Alice's. Nothing was "
                       "corrupted in transit, so transport integrity alone "
                       "cannot authenticate it -- the quantum witness is what "
                       "distinguishes this from the genuine article.")

    else:
        raise ValueError(f"Unknown attack: {attack!r}")

    return {"bits": corrupted, "description": description,
            "touched": touched, "attack": attack}


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_message(original_bits: list, received_bits: list,
                   tolerance: float = BIT_ERROR_TOLERANCE) -> dict:
    """
    Compare received bits against the signed original, bit by bit.

    Returns a per-bit fidelity table plus an aggregate verdict. This is the
    "which bits broke" view that turns a statistical score into something a
    human can read off the screen.
    """
    n = min(len(original_bits), len(received_bits))
    rows = []
    corrupted_indices = []

    for i in range(n):
        expected = int(original_bits[i]) & 1
        got = int(received_bits[i]) & 1
        ok = expected == got
        rows.append({"index": i, "expected": expected, "received": got, "ok": ok})
        if not ok:
            corrupted_indices.append(i)

    # A length mismatch is itself tampering: the message changed size.
    length_mismatch = len(original_bits) != len(received_bits)

    corrupted_count = len(corrupted_indices)
    total = n if n else 0
    fraction = corrupted_count / total if total else 0.0

    # VERIFIED means "within this channel's own noise floor", not "bit-perfect".
    #
    # It used to require zero differing bits, which is unachievable against real
    # hardware -- the noise model flips roughly 2% of bits on an honest transfer.
    # That was survivable at 24 characters, where 2% is about two bits and reads
    # as speckle. At 60 characters the same 2% is ten bits, so every honest
    # message reported SUSPECT and the demo's baseline looked compromised. The
    # threshold matches HONEST_MISMATCH_RATE in attack_metrics.py: the two now
    # agree on what "clean" means, and tests assert they stay in step.
    #
    # Short messages are cleared by EITHER test, not both. A fraction alone is
    # misleading at small n: one honest noise flip is 6% of "hi", which would
    # flag honest short traffic as SUSPECT, while the very same flip is 0.2% of
    # a 64-character message. So a message verifies when it is within the noise
    # floor proportionally OR when fewer bits differ than the flat allowance.
    #
    # The allowance stays small and unscaled on purpose -- see
    # MIN_TRANSPARENT_ERRORS. Scaling it with length made forgeries on short
    # messages verify clean, which is the failure this project exists to avoid.
    floor_bits = MIN_TRANSPARENT_ERRORS

    if length_mismatch:
        status = "TAMPERED"
    elif fraction <= NOISE_FLOOR or corrupted_count < floor_bits:
        status = "VERIFIED"
    elif fraction > TAMPER_FRACTION:
        status = "TAMPERED"
    else:
        status = "SUSPECT"

    return {
        "status": status,
        "bits": rows,
        "corrupted_indices": corrupted_indices,
        "corrupted_count": corrupted_count,
        "total_bits": n,
        "error_fraction": corrupted_count / total,
        "length_mismatch": length_mismatch,
        "tolerance": tolerance,
    }


# ---------------------------------------------------------------------------
# End-to-end
# ---------------------------------------------------------------------------

# Where a replay should pull its "earlier message" from. Defined in the
# signature layer because that is where replay semantics live; re-exported
# here so the attack helpers stay together.
from signature import replayable_prior_message  # noqa: F401,E402


# Re-exported so callers (and the UI) have one obvious place to reach for
# replay helpers without needing to know which module owns which piece. Both
# spellings exist in the codebase because the signature layer is the natural
# home for this, while the attack UI lives next to the other attack helpers.


def transit_bits(bits: list, shots: int = 256, noise_model=None,
                 inject_noise: bool = True, seed=None) -> list:
    """
    Send a bit pattern through the quantum channel and return what arrived.

    Each bit is teleported and sampled from its measured fidelity, so genuine
    hardware noise lands on top of anything an attacker did to the pattern
    beforehand.

    This is the single implementation of the channel. The single-shot path and
    the room path both call it -- the room previously carried its own copy,
    which meant a change to how noise was modelled had to be made in two
    places and the two could silently disagree.
    """
    rng = np.random.default_rng(seed if seed is not None else 20260101)
    model = noise_model if inject_noise else None

    transmitted = []
    for bit in bits:
        fidelity = transmit_bit(bit, shots=shots, noise_model=model)

        # Sample the received bit from the measured fidelity. With fidelity f
        # there are two equivalent readings -- receive the sent bit with
        # probability f, or receive its complement with probability 1-f.
        # Taking the first directly avoids the inversion bug that silently
        # turned an honest transfer into garbage.
        received = bit if rng.random() < fidelity else (bit ^ 1)
        transmitted.append(int(received))

    return transmitted


def transmit_message(message: str, attack: str = ATTACK_NONE, seed=None,
                     target_bits=None, substitute: str = None,
                     shots: int = 256, noise_model=DEFAULT_NOISE_MODEL,
                     inject_noise: bool = True, session_id: str = None,
                     issued_utc: str = None, replay_bits=None,
                     replay_session_id: str = None,
                     replay_issued_utc: str = None) -> dict:
    """
    Full pipeline: sign -> teleport -> attack -> decode -> verify.

    Each bit is teleported independently, which keeps every circuit at 3
    qubits regardless of message length. That matters: a single 192-qubit
    circuit would need an impractical state vector, whereas 192 independent
    3-qubit circuits are cheap. The trade-off is that the message qubits are
    not jointly entangled -- but a product state carries exactly the
    independent-bit fidelity this demo measures, so the physics reported is
    still correct.
    """
    original_bits = text_to_bits(message)
    attack_result = apply_attack(attack, original_bits, seed=seed,
                                 target_bits=target_bits, substitute=substitute,
                                 replay_bits=replay_bits)

    transmitted = transit_bits(
        attack_result["bits"], shots=shots,
        noise_model=noise_model, inject_noise=inject_noise, seed=seed,
    )

    verification = verify_message(original_bits, transmitted)

    # Witness check. Only meaningful for the forgery-by-substitution case,
    # where per-bit integrity is compared against Alice's ORIGINAL and so does
    # flag a different message -- but that comparison presumes the receiver
    # already holds Alice's plaintext. The witness is what removes that
    # presumption: Bob holds a physical copy instead, so the check stands on
    # quantum state rather than on an assumed plaintext.
    witness_result = None
    if attack in (ATTACK_SUBSTITUTE, ATTACK_REPLAY):
        try:
            from signature import sign_and_verify as _sav

            sig_attack = "forgery" if attack == ATTACK_SUBSTITUTE else "replay"

            # For a replay, hand the signature layer the ACTUAL earlier
            # session -- its signed bits, its session id, its issue time. That
            # is what makes the replayed signature genuine and lets the context
            # binding catch it, instead of the check passing vacuously.
            replay_prior = None
            if sig_attack == "replay" and replay_bits:
                replay_prior = {
                    "session_id": replay_session_id or "SESSION-PRIOR",
                    "message_bits": [int(b) for b in replay_bits],
                    "issued_utc": replay_issued_utc or "2025-12-24T09:15:00Z",
                }

            witness_result = _sav(
                [int(b) for b in original_bits],
                attack=sig_attack,
                seed=seed,
                n_signatures=2,
                shots=min(shots, 128),
                substitute=([int(b) for b in transmitted]
                            if sig_attack == "forgery" else None),
                session_id=session_id or "SESSION-CURRENT",
                issued_utc=issued_utc,
                replayed_from=replay_prior,
            )

            # Reduce to the fields the UI and report actually display.
            ctx = witness_result.get("context") or {}
            witness_result = {
                "verdict": witness_result["verdict"],
                "mismatches": witness_result.get("mismatches"),
                "total": witness_result.get("total"),
                "forgery_probability": witness_result.get("forgery_probability", 0.0),
                "presentation": witness_result.get("presentation", ""),
                "witness_passed": witness_result.get("witness_passed"),
                "context_verdict": ctx.get("verdict"),
                "context_expected": ctx.get("expected"),
                "context_presented": ctx.get("presented"),
                "replayed_from": witness_result.get("replayed_from"),
                "note": witness_result.get("note"),
            }
        except Exception as exc:  # never let the optional layer break a send
            witness_result = {"verdict": "UNAVAILABLE", "error": str(exc)}

    return {
        "message": message.strip(),
        "original_text": bits_to_text(original_bits),
        "received_text": bits_to_text(transmitted),
        "original_bits": original_bits,
        "received_bits": transmitted,
        "attack": attack,
        "attack_description": attack_result["description"],
        "attacked_bits": attack_result["touched"],
        "verification": verification,
        "witness": witness_result,
        "qubit_count": len(original_bits) * 3,
    }


def quick_demo():
    """Terminal demo: honest, forgery, replay, and channel manipulation."""
    message = "TRANSFER $5000"
    print("=" * 72)
    print(" MESSAGE LAYER DEMO")
    print("=" * 72)
    print(f"message: {message!r} ({len(text_to_bits(message))} bits, "
          f"{len(text_to_bits(message)) * 3} qubits)\n")

    cases = [
        ("Honest", ATTACK_NONE, None),
        ("Forgery", ATTACK_FORGERY, [40, 41, 42, 43]),
        ("Replay", ATTACK_REPLAY, None),
        ("Channel", ATTACK_CHANNEL, None),
    ]

    for label, atk, targets in cases:
        result = transmit_message(message, attack=atk, seed=7,
                                  target_bits=targets, shots=192)
        v = result["verification"]
        print(f"--- {label} ---")
        print(f"  {result['attack_description']}")
        print(f"  signed  : {result['original_text']}")
        print(f"  received: {result['received_text']}")
        print(f"  verdict : {v['status']}  "
              f"({v['corrupted_count']}/{v['total_bits']} bits differ)")
        if v["corrupted_indices"]:
            shown = v["corrupted_indices"][:6]
            print(f"  first differing bits: {shown}")
        print()


if __name__ == "__main__":
    quick_demo()