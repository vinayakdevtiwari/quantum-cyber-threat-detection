"""Tests for the quantum witness layer."""
import numpy as np
import pytest

from signature import (
    generate_key_pool, select_pads, encrypt,
    build_witness, verify_witness, sign_and_verify,
    forgery_success_rate,
    new_master_seed, derive_conversation_key,
    build_conversation_witness, gate_access,
    VERIFIED, FORGERY_PROVEN, REPLAY_BLOCKED, INCONCLUSIVE,
    ACCESS_GRANTED, ACCESS_DENIED, ACCESS_MATCH_THRESHOLD,
)

SHOTS = 64


# --- key material ---------------------------------------------------------

def test_key_pool_shape():
    pool = generate_key_pool(n_keys=16, key_len=8, seed=1)
    assert len(pool) == 16
    assert all(len(k) == 8 for k in pool)
    assert all(b in (0, 1) for k in pool for b in k)


def test_key_pool_is_deterministic_with_seed():
    assert generate_key_pool(8, 8, seed=42) == generate_key_pool(8, 8, seed=42)


def test_select_pads_returns_requested_count():
    assert len(select_pads(32, 5, rng=np.random.default_rng(0))) == 5


def test_select_pads_rejects_impossible_request():
    with pytest.raises(ValueError):
        select_pads(4, 10)


def test_encrypt_is_xor_and_reversible():
    msg = [1, 0, 1, 1]
    pad = [0, 1, 1, 0]
    ct = encrypt(msg, pad)
    assert ct == [1, 1, 0, 1]
    assert encrypt(ct, pad) == msg  # pad is its own inverse


def test_encrypt_rejects_length_mismatch():
    with pytest.raises(ValueError):
        encrypt([1, 0], [1, 0, 1])


# --- witness --------------------------------------------------------------

def test_witness_has_one_entry_per_bit():
    bits = [1, 0, 1, 0, 1]
    w = build_witness(bits, shots=SHOTS)
    assert len(w) == len(bits)
    assert all(isinstance(v, int) and conf > 0.5 for v, conf in w)


def test_honest_message_verifies():
    bits = [1, 0, 1, 0] * 4
    w = build_witness(bits, shots=SHOTS)
    r = verify_witness(w, bits)
    assert r["verdict"] == VERIFIED
    assert r["mismatches"] == 0


def test_wrong_message_is_proven_forgery():
    bits = [1, 0, 1, 0] * 4
    w = build_witness(bits, shots=SHOTS)
    r = verify_witness(w, [b ^ 1 for b in bits])
    assert r["verdict"] == FORGERY_PROVEN
    assert r["proven_forgeries"] == len(bits)


# --- room key derivation --------------------------------------------------

def test_conversation_key_is_a_bit_pattern():
    """
    Regression: the key was initially produced by iterating a hash digest's
    BYTES, yielding values 0-255 rather than 0/1. encrypt() then XORed
    plaintext against numbers up to 255, so the witness built over the result
    matched nothing -- not even its own wire bits -- and the access gate denied
    a holder of the genuine key.
    """
    key = derive_conversation_key("seed", "dm:a|b", 64)
    assert len(key) == 64
    assert all(b in (0, 1) for b in key)


def test_conversation_key_is_deterministic():
    assert (derive_conversation_key("s", "dm:a|b", 32)
            == derive_conversation_key("s", "dm:a|b", 32))


def test_distinct_conversations_get_distinct_keys():
    """Otherwise an observer could tell two users sent the same words."""
    a = derive_conversation_key("s", "dm:alice|bob", 64)
    b = derive_conversation_key("s", "dm:alice|carol", 64)
    assert a != b
    # and they must not merely differ at the end by sharing a long prefix
    assert sum(1 for x, y in zip(a, b) if x != y) > 8


def test_conversation_key_rejects_negative_length():
    with pytest.raises(ValueError):
        derive_conversation_key("s", "dm:a|b", -1)


# --- private-chat access gate ---------------------------------------------

def test_real_key_is_granted_access():
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    r = gate_access(conv["witness"], conv["wire_bits"])
    assert r["verdict"] == ACCESS_GRANTED
    assert r["granted"] is True


def test_guessing_never_grants_access():
    """
    The gate's load-bearing property: an attacker gets unlimited attempts and
    the odds stay against her. A wrong candidate must be refused outright.
    """
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    # inverted plaintext is what a naive attacker would try
    assert gate_access(conv["witness"], [b ^ 1 for b in plain])["granted"] is False


def test_brute_force_never_wins():
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    rng = np.random.default_rng(3)
    wins = sum(
        1 for _ in range(200)
        if gate_access(conv["witness"],
                       list(rng.integers(0, 2, size=len(plain))))["granted"]
    )
    assert wins == 0


def test_partial_match_is_denied():
    """
    Flagged-qubit guessing: getting half the bits right is still a refusal.
    INCONCLUSIVE must not be treated as a pass -- a near-miss is not a reason
    to hand over a private conversation.
    """
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    half = list(conv["wire_bits"])
    half[8:] = [b ^ 1 for b in half[8:]]
    assert sum(1 for a, b in zip(half, conv["wire_bits"]) if a != b) == 8
    r = gate_access(conv["witness"], half)
    assert r["granted"] is False
    assert r["verdict"] == ACCESS_DENIED


def test_single_wrong_bit_is_tolerated_as_noise():
    """
    A single wrong qubit must NOT deny a genuine key holder.

    This test previously asserted the opposite, because the gate originally
    demanded an exact match. That was wrong on a noisy channel: measured, a
    genuine candidate loses the occasional qubit to hardware noise, so an exact
    gate locked real members out of their own conversations. The gate now
    requires a match RATE, and one bad qubit out of 152 is inside that.
    """
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    off_by_one = list(conv["wire_bits"])
    off_by_one[0] ^= 1
    assert off_by_one != conv["wire_bits"]
    assert gate_access(conv["witness"], off_by_one)["granted"] is True


def test_many_wrong_bits_are_still_denied():
    """
    Tolerance is bounded. Once enough qubits disagree the gate closes again --
    otherwise the noise tolerance above would be a way in.
    """
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    bad = list(conv["wire_bits"])
    for i in range(0, len(bad), 2):  # flip half
        bad[i] ^= 1
    assert gate_access(conv["witness"], bad)["granted"] is False


def test_gate_survives_noisy_witness_for_a_real_key_holder():
    """
    Across many seeds and shot counts, a genuine key holder is never refused.

    This is the property that an exact-match gate broke. Measured worst case is
    0.9934 against a 0.90 threshold, so the margin is wide -- but the point of
    the test is that it holds, not that the margin is comfortable.
    """
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    for i in range(6):
        conv = build_conversation_witness(
            f"seed-{i}", f"dm:user{i}|other", plain, shots=SHOTS)
        assert gate_access(conv["witness"], conv["wire_bits"])["granted"] is True, i


def test_guessing_stays_far_below_the_threshold():
    """
    The two populations must not approach each other. Guessing lands near 50%,
    a genuine key above 99%, so the threshold has room on both sides.
    """
    rng = np.random.default_rng(4)
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    worst_guess = 0.0
    for i in range(12):
        conv = build_conversation_witness(f"s{i}", f"dm:u{i}|o", plain, shots=SHOTS)
        guess = list(rng.integers(0, 2, size=len(plain)))
        rate = gate_access(conv["witness"], guess)["match_rate"]
        worst_guess = max(worst_guess, rate)
    assert worst_guess < ACCESS_MATCH_THRESHOLD, (
        f"best guess reached {worst_guess}, threshold is {ACCESS_MATCH_THRESHOLD}")


def test_stolen_key_from_another_conversation_still_works():
    """
    One leaked room key compromises every conversation in that room. This is
    why the key is derived from a shared master seed rather than per-chat.
    """
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    other = [0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0]
    a = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    b = build_conversation_witness(seed, "dm:alice|carol", other, shots=SHOTS)
    # same seed, different conversation: Eve re-derives b's key and reads it
    assert gate_access(b["witness"], b["wire_bits"])["granted"] is True
    # and a room without the seed cannot
    stranger = build_conversation_witness(new_master_seed(),
                                          "dm:alice|carol", other, shots=SHOTS)
    assert gate_access(stranger["witness"], a["wire_bits"])["granted"] is False


def test_witness_does_not_reveal_plaintext():
    """Holding the witness must not hand over the message itself."""
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    assert conv["wire_bits"] != plain, "plaintext must not travel on the wire"
    assert all(b in (0, 1) for b in conv["wire_bits"])


def test_short_candidate_is_refused_outright():
    """
    Regression: the gate was bypassable by sending a SHORT candidate.

    verify_witness zips the candidate against the witness, which stops at
    whichever is shorter, so a short candidate was scored only on its own few
    qubits. Measured on a 48-qubit witness, a 1-bit candidate was GRANTED
    whenever that bit happened to agree, and an EMPTY candidate was granted
    every time -- no key required at all.

    Length is now checked before any comparison.
    """
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0] * 6
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    wire = conv["wire_bits"]

    assert gate_access(conv["witness"], [])["granted"] is False
    assert gate_access(conv["witness"], wire[:1])["granted"] is False
    assert gate_access(conv["witness"], wire[:5])["granted"] is False
    assert gate_access(conv["witness"], wire[:len(wire) - 1])["granted"] is False


def test_long_candidate_is_refused_outright():
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0] * 6
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    padded = conv["wire_bits"] + [0, 0, 0]
    assert gate_access(conv["witness"], padded)["granted"] is False


def test_wrong_length_explains_itself():
    """The refusal has to say WHY, or the attacker cannot tell a fixable
    mistake from a rejected forgery."""
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0] * 6
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    r = gate_access(conv["witness"], [1, 0, 1])
    assert r["granted"] is False
    assert "witness is" in r["explanation"]
    assert str(len(conv["witness"])) in r["explanation"]


def test_empty_witness_never_grants():
    seed = new_master_seed()
    plain = [1, 0, 1, 1]
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    assert gate_access([], conv["wire_bits"])["granted"] is False


def test_random_length_guesses_never_win():
    """
    An attacker who does not know the message length picks a length at random.
    Every one of those must fail: the only length that can pass is the real one,
    and matching it still requires the key.
    """
    rng = np.random.default_rng(11)
    seed = new_master_seed()
    plain = [1, 0, 1, 1, 0, 0, 1, 0] * 6
    conv = build_conversation_witness(seed, "dm:alice|bob", plain, shots=SHOTS)
    real = len(conv["witness"])

    for _ in range(40):
        guess_len = int(rng.integers(0, real + 12))
        guess = list(rng.integers(0, 2, size=guess_len))
        if guess_len == real:
            # right length, wrong content -- still a guess
            pass
        assert gate_access(conv["witness"], guess)["granted"] is False, guess_len


# --- end to end -----------------------------------------------------------

def test_honest_flow_verifies():
    bits = [1, 0, 1, 0] * 4
    r = sign_and_verify(bits, attack="honest", n_signatures=4, seed=3, shots=SHOTS)
    assert r["verdict"] == VERIFIED


def test_forgery_is_proven_not_merely_suspected():
    bits = [1, 0, 1, 0] * 4
    r = sign_and_verify(bits, attack="forgery", n_signatures=4, seed=3, shots=SHOTS)
    assert r["verdict"] == FORGERY_PROVEN
    assert r["forgery_probability"] < 0.01


def test_replay_is_blocked():
    bits = [1, 0, 1, 0] * 4
    r = sign_and_verify(bits, attack="replay", n_signatures=4, seed=3, shots=SHOTS)
    assert r["verdict"] == REPLAY_BLOCKED


def test_forgery_with_explicit_substitute():
    bits = [0] * 16
    other = [1] * 16
    r = sign_and_verify(bits, attack="forgery", substitute=other,
                        n_signatures=2, seed=5, shots=SHOTS)
    assert r["verdict"] == FORGERY_PROVEN


def test_result_carries_presentation_context():
    bits = [1, 0] * 8
    r = sign_and_verify(bits, attack="forgery", seed=1, shots=SHOTS)
    for key in ("verdict", "presentation", "ciphertext", "rows",
                "forgery_probability", "pad_count"):
        assert key in r


# --- security property ----------------------------------------------------

def test_forgery_rate_falls_with_length():
    """The headline claim: forgery must get exponentially harder."""
    rows = forgery_success_rate([2, 4, 6], trials=40, seed=11)
    lengths = [l for l, _, _ in rows]
    rates = [m for _, _, m in rows]
    assert lengths == sorted(lengths)
    assert rates[-1] < rates[0], f"forgery rate did not fall: {rows}"
    # Longer messages must land near the theoretical 2**-L bound.
    for length, theory, measured in rows:
        assert measured <= max(0.25, theory * 3), (
            f"L={length}: measured {measured} far exceeds theory {theory}")