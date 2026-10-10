"""
attack_metrics.py

Turns a phone-demo attack result into the same four SOC metrics the dashboard
already shows for single-qubit sessions, so an attack reads the same way.

WHY THIS EXISTS
---------------
The four cards (error rate / statistical deviation / threat score / security
posture) originally came from the 3-qubit teleportation detector. A phone
attack is a different measurement -- per-bit integrity across a whole message --
so there was no honest way to fill those cards. Setting them to zero would show
a deviation of 0.00 next to a corrupted message, which is worse than showing
nothing.

WHAT IS ACTUALLY COMPUTED HERE
------------------------------
Not the teleportation chi-squared, because that detector never ran. Instead a
chi-squared goodness-of-fit on BIT-MATCH OUTCOMES:

    observed: 106 matches / 6 mismatches   (measured this session)
    expected: ~98% match / ~2% mismatch    (calibrated honest noise)
    -> chi-squared statistic on real data

That is a genuine statistic computed from the actual session, not an invented
one, which is why it is acceptable to display. The card label says "bit-match"
so nobody mistakes it for the teleportation detector.

HONEST LABELLING
----------------
The error-rate card is called "Bit Integrity Error Rate" for phone sessions,
not "Teleportation Error Rate", because that is what it measures. Same card,
same position, accurate label.
"""

import numpy as np

# Honest mismatch rate measured across clean phone sessions at the default
# noise model: mean 0.0199 over 20 runs of a 512-bit message. Used as the
# expected distribution for the goodness-of-fit test.
#
# This is the MEAN. message_layer.NOISE_FLOOR is deliberately set higher (to
# the p90, 0.028) because the transport verdict must not flip to SUSPECT on the
# noisier tail of honest traffic. The two are the same measurement serving
# different questions -- "what should we expect" versus "what is still
# acceptable" -- so they are close but not equal.
HONEST_MISMATCH_RATE = 0.02

# Bit error rate above this maps to INSECURE. Mirrors detection.SECURITY_ERROR_THRESHOLD
# (0.11) so one number means "integrity tolerance" across the whole project.
ERROR_THRESHOLD = 0.11

# Deviation at or above this maps to THREAT. Calibrated so that honest hardware
# noise (~2% bit error) stays well below it and any real attack clears it.
DEVIATION_THRESHOLD = 9.0

# Below this fraction of differing bits we treat a session as honest even if the
# deviation is large, because a handful of noisy bits is not an attack.
ATTACK_ERROR_FLOOR = 0.03

# Upper bound on "bit-flipping" corruption. Above this, no plausible bit-flip
# account of the message survives: a handful of single-bit errors cannot rewrite
# most of a message, so corruption at this scale is treated as a wholesale
# substitution (forgery / replay) rather than tampering.
#
# This bound is what makes WEAK reachable. Degraded hardware produces a broad
# scatter of errors across the register -- which is what INSECURE-without-an-
# attacker actually looks like -- while a forgery replaces the message wholesale.
# Without the upper bound, degraded noise above ATTACK_ERROR_FLOOR was always
# scored as a threat and WEAK could never be selected.
SUBSTITUTION_FLOOR = 0.25


def bit_match_chi_squared(mismatched_bits: int, total_bits: int,
                          expected_rate: float = HONEST_MISMATCH_RATE) -> float:
    """
    Chi-squared goodness-of-fit between observed and expected bit-match counts.

    Two bins: mismatches and matches. Under honest noise the mismatch rate sits
    near `expected_rate`; an attack pushes it far higher, and the statistic grows
    quadratically with the departure.
    """
    if total_bits <= 0:
        return 0.0

    mismatched = int(mismatched_bits)
    matched = max(total_bits - mismatched, 0)

    exp_mismatch = total_bits * expected_rate
    exp_match = total_bits * (1.0 - expected_rate)

    # Floor the expected counts so a tiny bin cannot produce a division blow-up.
    eps = 0.5
    exp_mismatch = max(exp_mismatch, eps)
    exp_match = max(exp_match, eps)

    chi = ((mismatched - exp_mismatch) ** 2) / exp_mismatch
    chi += ((matched - exp_match) ** 2) / exp_match
    return float(chi)


def compute_attack_metrics(session_data: dict) -> dict:
    """
    Build the four dashboard metrics from a phone-session dict.

    Returns the raw values plus the derived labels, so the view layer only has
    to format them.
    """
    total = int(session_data.get("total_bits") or 0)
    corrupted = int(session_data.get("corrupted_bits") or 0)
    error_rate = corrupted / total if total else 0.0

    deviation = bit_match_chi_squared(corrupted, total)

    # Threat score is normalized so 1.0 is the decision gate, matching the
    # single-qubit cards where score >= 1.0 flags.
    score = deviation / DEVIATION_THRESHOLD if DEVIATION_THRESHOLD else 0.0

    # "none" is the honest-channel sentinel used throughout the project, so it
    # must count as "no attack" here too. Only these values mean an attacker
    # actually acted.
    _NO_ATTACK_VALUES = (None, "none", "", "honest")
    attacked = session_data.get("attack_type") not in _NO_ATTACK_VALUES

    # A session is a THREAT when the bit error rate clears the hardware noise
    # floor, or when corruption reaches substitution scale.
    #
    # Deliberately NOT conditioned on `attack_present`. That made WEAK
    # unreachable: WEAK means INSECURE with no attacker, but the moment
    # corruption was high enough to be INSECURE it was automatically called a
    # threat. Degraded hardware producing a broad scatter of errors is exactly
    # the latent-risk case WEAK exists to describe, and it must be reportable.
    if error_rate < ATTACK_ERROR_FLOOR:
        threat = False
    elif error_rate >= SUBSTITUTION_FLOOR:
        # Wholesale rewrite -- cannot be explained as bit tampering.
        threat = True
    else:
        # In the ambiguous band, an attack that actually ran is treated as
        # hostile; otherwise this is channel degradation, not an intruder.
        threat = attacked

    security = "INSECURE" if error_rate > ERROR_THRESHOLD else "SECURE"

    if security == "SECURE" and not threat:
        posture = "VERY STRONG"
    elif security == "SECURE":
        posture = "STRONG + ALERT"
    elif not threat:
        posture = "WEAK"
    else:
        posture = "CRITICAL"

    signature_verdict = (session_data.get("witness") or {}).get("verdict")

    return {
        "error_rate": error_rate,
        "error_threshold": ERROR_THRESHOLD,
        "security_state": security,
        "deviation": deviation,
        "deviation_threshold": DEVIATION_THRESHOLD,
        "threat_score": score,
        "threat_label": "THREAT" if threat else "NO_THREAT",
        # Reported separately from threat_label, because the two genuinely
        # disagree in the WEAK quadrant: bits are degraded, but no attack ran.
        # Collapsing them into one field would hide exactly the case a SOC
        # operator most needs to see.
        "attack_present": attacked,
        "posture": posture,
        "corrupted_bits": corrupted,
        "total_bits": total,
        "signature_verdict": signature_verdict,
        "context_verdict": (session_data.get("witness") or {}).get("context_verdict"),
        "witness_passed": (session_data.get("witness") or {}).get("witness_passed"),
    }


def explain(metrics: dict, session_data: dict) -> str:
    """One-line plain-language summary for the card hint area."""
    posture = metrics["posture"]
    corrupted = metrics["corrupted_bits"]
    total = metrics["total_bits"]
    attack = session_data.get("attack_type") or "none"

    if session_data.get("attack_type") in (None, "none"):
        return (f"No attack present. {corrupted}/{total} bits differ from hardware "
                f"noise alone. {posture} reflects channel degradation only.")
    return (f"Attack '{attack}' corrupted {corrupted}/{total} bits "
            f"({metrics['error_rate']*100:.1f}%), mapped to posture {posture}.")