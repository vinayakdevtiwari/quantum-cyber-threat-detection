"""
detection.py
The statistical detection layer described on your Technical Approach slide:

  Compare with Expected Distribution -> Calculate Statistical Deviation
  -> Apply Calibrated Threshold -> Threat Score -> Accept / Flag-Reject

We use a chi-squared-style distance between the observed and expected
measurement-outcome distributions. This is a well-understood, easy-to-explain
statistic -- good for judge Q&A.
"""

import numpy as np


def teleportation_error_rate(observed_counts: dict, message_state: str):
    """
    SECURITY STATE metric (distinct from the Threat Detector below).

    A correctly-teleported qubit should end up measured as `message_state`.
    This computes the fraction of shots where it did NOT -- i.e. the
    protocol's own error rate, independent of any specific attack pattern.

    This is the QDS analogue of QBER (quantum bit error rate) in QKD
    security proofs: every such protocol has a noise threshold above which
    its security guarantees no longer hold, REGARDLESS of whether an
    attacker is present. High noise alone can break the assumptions the
    protocol relies on.

    Qiskit prints count bitstrings as c2 c1 c0 (highest classical bit
    first, i.e. LEFTMOST character), not c0 c1 c2. The final, corrected,
    teleported qubit is measured into classical bit 2, so it's the
    leftmost character in each key -- bitstring[0], not bitstring[-1].
    """
    total = sum(observed_counts.values())
    mismatches = 0
    for bitstring, n in observed_counts.items():
        teleported_bit = bitstring[0]  # leftmost = clbit 2 (highest bit)
        if teleported_bit != message_state:
            mismatches += n
    return mismatches / total


# Representative security threshold. Real QDS security proofs derive a
# specific bound analytically for their scheme; treat it as a stand-in
# and say so if asked -- cite it as "modeled on QKD-style QBER thresholds
# (~11%, as in BB84 security proofs)" rather than claiming it's derived
# for this exact protocol.
SECURITY_ERROR_THRESHOLD = 0.11


def security_state(error_rate: float, threshold: float = SECURITY_ERROR_THRESHOLD):
    """
    Independent of any attack detection: are the protocol's own security
    assumptions satisfied right now? SECURE if error rate is within the
    tolerance the security proof requires, INSECURE otherwise.
    """
    return "SECURE" if error_rate <= threshold else "INSECURE"


def counts_to_distribution(counts: dict, num_bits: int = 3):
    """
    Convert Qiskit's raw counts dict (e.g. {'011': 40, '101': 12, ...})
    into a fixed-length probability vector over all possible bitstrings,
    so honest and attacked runs can be compared apples-to-apples even if
    one produced outcomes the other didn't.
    """
    total = sum(counts.values())
    all_keys = [format(i, f"0{num_bits}b") for i in range(2 ** num_bits)]
    dist = np.array([counts.get(k, 0) / total for k in all_keys])
    return dist


def chi_squared_deviation(observed_counts: dict, expected_counts: dict, num_bits: int = 3):
    """
    Chi-squared-style statistic between observed and expected distributions.
    Higher value = more deviation from what an honest session should look like.
    """
    obs = counts_to_distribution(observed_counts, num_bits)
    exp = counts_to_distribution(expected_counts, num_bits)

    # Floor the denominator at 1% probability, not a near-zero epsilon.
    # A true near-zero epsilon makes the statistic blow up from ordinary
    # sampling noise in rare bins; a modest floor keeps rare-outcome bins
    # from dominating the statistic while still penalizing real shifts.
    exp_safe = np.maximum(exp, 0.01)
    chi_sq = np.sum(((obs - exp) ** 2) / exp_safe)
    return float(chi_sq)


def calibrate_threshold(honest_deviations, attacked_deviations, target_fpr: float = 0.05):
    """
    Derive a threshold analytically from simulated trial data rather than
    guessing a number. We pick the threshold at the (1 - target_fpr)
    percentile of the HONEST deviation distribution, so at most `target_fpr`
    fraction of honest sessions get incorrectly flagged.

    Run this offline over many trials (see calibrate.py) and hardcode the
    resulting number into your app/config -- don't recompute it live.
    """
    honest_deviations = np.array(honest_deviations)
    threshold = np.percentile(honest_deviations, (1 - target_fpr) * 100)
    return float(threshold)


def threat_score(deviation: float, threshold: float):
    """
    Combine the raw deviation and the calibrated threshold into a single
    normalized score in [0, 1+]. A score >= 1.0 means the session exceeded
    the calibrated threshold and should be flagged.
    """
    if threshold == 0:
        return 0.0
    return deviation / threshold


def verdict(score: float):
    return "ANOMALOUS - FLAG/REJECT" if score >= 1.0 else "NORMAL - ACCEPT"
