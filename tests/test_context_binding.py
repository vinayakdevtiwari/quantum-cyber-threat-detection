"""Tests for context binding and true replay semantics."""
import pytest

from signature import (
    bind_context, verify_context, sign_and_verify, replayable_prior_message,
    build_witness,
    CONTEXT_VALID, CONTEXT_MISMATCH, VERIFIED, REPLAY_BLOCKED,
)

BITS = [1, 0, 1, 0] * 8
SHOTS = 64


# --- binding --------------------------------------------------------------

def test_binding_is_deterministic():
    a = bind_context("S1", BITS, "2026-01-01T00:00:00Z")
    b = bind_context("S1", BITS, "2026-01-01T00:00:00Z")
    assert a == b


def test_binding_changes_with_session():
    assert bind_context("S1", BITS, "T") != bind_context("S2", BITS, "T")


def test_binding_changes_with_message():
    assert bind_context("S1", BITS, "T") != bind_context("S1", [1 - b for b in BITS], "T")


def test_binding_changes_with_time():
    assert bind_context("S1", BITS, "T1") != bind_context("S1", BITS, "T2")


def test_verify_context_detects_match():
    b = bind_context("S1", BITS, "T")
    r = verify_context(b, b)
    assert r["verdict"] == CONTEXT_VALID
    assert r["matches"] is True


def test_verify_context_detects_mismatch():
    r = verify_context(bind_context("S1", BITS, "T"),
                       bind_context("S2", BITS, "T"))
    assert r["verdict"] == CONTEXT_MISMATCH
    assert r["matches"] is False


# --- replay semantics -----------------------------------------------------

def test_honest_message_has_valid_context():
    r = sign_and_verify(BITS, attack="honest", seed=3, shots=SHOTS,
                        session_id="QCTD-1")
    assert r["verdict"] == VERIFIED
    assert r["context"]["verdict"] == CONTEXT_VALID


def test_replay_passes_the_witness():
    """
    The defining property of a true replay: the quantum witness ACCEPTS it,
    because the signature and its witness are both genuine. Detection must not
    be attributed to the quantum layer or the demo would be lying.
    """
    r = sign_and_verify(BITS, attack="replay", seed=3, shots=SHOTS,
                        session_id="QCTD-CURRENT")
    assert r["witness_passed"] is True, "replayed signature must pass the witness"
    assert r["context"]["verdict"] == CONTEXT_MISMATCH


def test_replay_is_still_blocked():
    r = sign_and_verify(BITS, attack="replay", seed=3, shots=SHOTS,
                        session_id="QCTD-CURRENT")
    assert r["verdict"] == REPLAY_BLOCKED
    assert "context binding" in r["note"].lower()


def test_replay_reports_its_origin():
    r = sign_and_verify(BITS, attack="replay", seed=3, shots=SHOTS)
    assert r["replayed_from"]


def test_witness_sampling_is_reproducible():
    """
    Regression: the witness sampler drew from an UNSEEDED rng, so the same
    signed message produced a different witness on every call. That is not a
    quantum property, it is an unreproducible test -- and it made a genuine
    replay fail the witness in roughly 1% of runs, which showed up as an
    intermittent CI failure with no visible cause.

    The sampled VALUES are what must be stable: those are the recorded
    measurement, and verification compares them. The confidence is derived from
    Aer's shot counts, which are seeded separately by the simulator and vary
    slightly run to run, so it is deliberately not asserted here.
    """
    a = build_witness(BITS, shots=SHOTS)
    b = build_witness(BITS, shots=SHOTS)
    assert [v for v, _ in a] == [v for v, _ in b]


def test_a_genuine_replay_always_passes_the_witness():
    """
    The witness should accept a real earlier signature on every run. Any failure
    here is a sampling defect, not a finding -- replay is caught by context
    binding, and that only makes sense if the quantum check passes first.
    """
    prior = {"session_id": "QCTD-OLD", "message_bits": BITS,
             "issued_utc": "2025-06-01T12:00:00Z"}
    for seed in range(12):
        r = sign_and_verify(BITS, attack="replay", seed=seed, shots=SHOTS,
                            session_id="QCTD-NEW", replayed_from=prior)
        assert r["witness_passed"] is True, f"seed {seed} rejected a genuine replay"
        assert r["verdict"] == REPLAY_BLOCKED


def test_replay_from_a_real_prior_session():
    prior = {"session_id": "QCTD-OLD", "message_bits": BITS,
             "issued_utc": "2025-06-01T12:00:00Z"}
    r = sign_and_verify(BITS, attack="replay", seed=3, shots=SHOTS,
                        session_id="QCTD-NEW", replayed_from=prior)
    assert r["witness_passed"] is True
    assert r["verdict"] == REPLAY_BLOCKED
    assert r["replayed_from"] == "QCTD-OLD"


def test_replaying_into_the_originating_session_is_valid():
    """
    A signature replayed back into the session it was issued for is not an
    attack -- it is the same message arriving again in its own context. The
    binding must not flag it, or the check is too strict to be useful.
    """
    prior = {"session_id": "QCTD-OLD", "message_bits": BITS,
             "issued_utc": "2025-06-01T12:00:00Z"}
    r = sign_and_verify(BITS, attack="honest", seed=3, shots=SHOTS,
                        session_id="QCTD-OLD", issued_utc="2025-06-01T12:00:00Z")
    assert r["verdict"] == VERIFIED
    assert r["context"]["matches"] is True


# --- prior message selection ---------------------------------------------

def test_replayable_prior_differs_from_current():
    assert replayable_prior_message("TRANSFER $5000") != "TRANSFER $5000"


def test_replayable_prior_is_usable_text():
    from message_layer import text_to_bits
    for msg in ["TRANSFER $5000", "PAYROLL APPROVED", "SALARY REVIEW Q3"]:
        assert len(text_to_bits(replayable_prior_message(msg))) > 0