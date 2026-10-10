"""Tests for the quantum witness layer."""
import numpy as np
import pytest

from signature import (
    generate_key_pool, select_pads, encrypt,
    build_witness, verify_witness, sign_and_verify,
    forgery_success_rate,
    VERIFIED, FORGERY_PROVEN, REPLAY_BLOCKED, INCONCLUSIVE,
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