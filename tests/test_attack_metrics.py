"""Tests for the Live Attack telemetry metrics."""
import pytest

from attack_metrics import (
    bit_match_chi_squared, compute_attack_metrics, explain,
    HONEST_MISMATCH_RATE, ERROR_THRESHOLD, DEVIATION_THRESHOLD,
    ATTACK_ERROR_FLOOR,
)


def sess(attack, corrupted, total=112, witness=None):
    return {
        "attack_type": attack,
        "corrupted_bits": corrupted,
        "total_bits": total,
        "witness": witness or {},
        "original_message": "TRANSFER $5000",
        "received_message": "TRANSFER $5008",
    }


# --- chi-squared ----------------------------------------------------------

def test_chi_squared_grows_with_corruption():
    values = [bit_match_chi_squared(c, 112) for c in (0, 5, 20, 50)]
    assert values == sorted(values), f"not monotonic: {values}"


def test_chi_squared_minimal_near_expected_rate():
    """A session sitting exactly at the honest rate should score ~0."""
    expected_bits = int(112 * HONEST_MISMATCH_RATE)
    assert bit_match_chi_squared(expected_bits, 112) < 1.0


def test_chi_squared_safe_on_empty():
    assert bit_match_chi_squared(0, 0) == 0.0


# --- honest sessions ------------------------------------------------------

def test_honest_session_does_not_flag():
    for corrupted in (0, 1, 2, 3):
        m = compute_attack_metrics(sess("none", corrupted))
        assert m["threat_label"] == "NO_THREAT", f"{corrupted} bits flagged"
        assert m["posture"] == "VERY STRONG"


# --- attacked sessions ----------------------------------------------------

@pytest.mark.parametrize("attack", [
    "forgery", "impersonation", "replay",
    "channel_manipulation", "forgery_substitute",
])
def test_every_attack_flags(attack):
    m = compute_attack_metrics(sess(attack, 8))
    assert m["threat_label"] == "THREAT"
    assert m["threat_score"] >= 1.0


def test_small_attack_stays_secure_and_alerts():
    m = compute_attack_metrics(sess("forgery", 8))
    assert m["security_state"] == "SECURE"
    assert m["posture"] == "STRONG + ALERT"


def test_large_corruption_is_critical():
    m = compute_attack_metrics(sess("channel_manipulation", 30))
    assert m["security_state"] == "INSECURE"
    assert m["posture"] == "CRITICAL"


# --- postures -------------------------------------------------------------

def test_all_four_postures_reachable():
    # Degraded-but-not-attacked corruption has to stay below the substitution
    # floor: a broad scatter of hardware errors is INSECURE without being a
    # wholesale message rewrite, which is what WEAK describes.
    degraded = int(112 * ERROR_THRESHOLD) + 4
    assert degraded < 112 * 0.25

    postures = {
        compute_attack_metrics(sess("none", 2))["posture"],
        compute_attack_metrics(sess("forgery", 8))["posture"],
        compute_attack_metrics(sess("none", degraded))["posture"],
        compute_attack_metrics(sess("channel_manipulation", 30))["posture"],
    }
    assert postures == {"VERY STRONG", "STRONG + ALERT", "WEAK", "CRITICAL"}


def test_attack_below_floor_is_not_a_threat():
    """A real attack that only moved noise-level bits must not read as one."""
    below = int(112 * ATTACK_ERROR_FLOOR)
    m = compute_attack_metrics(sess("forgery", max(below - 1, 0)))
    assert m["threat_label"] == "NO_THREAT"
    # The attack is still recorded even though it did not cross the gate.
    assert m["attack_present"] is True


def test_degraded_channel_without_attack_is_weak():
    """
    WEAK = INSECURE with no attacker. This is the latent-risk case: the channel
    is too noisy to trust, but nobody is attacking. It must be reachable, or a
    SOC operator has no way to express "broken, not attacked".
    """
    degraded = int(112 * ERROR_THRESHOLD) + 4
    m = compute_attack_metrics(sess("none", degraded))
    assert m["security_state"] == "INSECURE"
    assert m["attack_present"] is False
    assert m["posture"] == "WEAK"


def test_wholesale_corruption_is_threat_even_without_attack_flag():
    """
    Corruption past the substitution floor cannot be explained as scattered
    hardware error, so it is treated as a rewrite regardless of what ran.
    """
    m = compute_attack_metrics(sess("none", 40))
    assert m["error_rate"] >= 0.25
    assert m["posture"] == "CRITICAL"


# --- signature passthrough ------------------------------------------------

def test_replay_carries_signature_verdict():
    w = {"verdict": "REPLAY BLOCKED", "witness_passed": True,
         "context_verdict": "CONTEXT MISMATCH"}
    m = compute_attack_metrics(sess("replay", 8, witness=w))
    assert m["signature_verdict"] == "REPLAY BLOCKED"
    assert m["context_verdict"] == "CONTEXT MISMATCH"
    assert m["witness_passed"] is True


# --- explain --------------------------------------------------------------

def test_explain_mentions_attack_and_counts():
    text = explain(compute_attack_metrics(sess("forgery", 8)), sess("forgery", 8))
    assert "forgery" in text and "8/112" in text


def test_explain_for_honest_session():
    text = explain(compute_attack_metrics(sess("none", 2)), sess("none", 2))
    assert "No attack" in text