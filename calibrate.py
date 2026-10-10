"""
calibrate.py
Run this ONCE offline to derive a calibrated threshold from many simulated
trials, per the "Apply Calibrated Threshold" step on your slide and the
"derive threshold analytically & validate over many simulated trials"
strategy on your feasibility slide.

Now pools honest AND attacked trials across BOTH measurement bases (Z and
X), not just both noise models. A phase-flip attack (impersonation) is
invisible in the Z-basis but shows up as a bit-flip in the X-basis, and
vice versa for bit-flip-style attacks -- so the threshold has to be valid
across both, since app.py picks the basis randomly per session.

Usage:
    python calibrate.py
"""

import numpy as np
from simulator import run_session, stable_expected_distribution, DEFAULT_NOISE_MODEL, DEGRADED_NOISE_MODEL
from attacks import ATTACKS
from detection import chi_squared_deviation, calibrate_threshold

N_TRIALS = 200
SHOTS_PER_TRIAL = 512
MESSAGE_STATE = "1"
BASES = ["Z", "X"]


def main():
    # IMPORTANT: pool honest sessions across BOTH noise models (default +
    # degraded) AND BOTH measurement bases (Z + X). The Threat Detector's
    # job is to catch ATTACK-shaped deviations, not any deviation --
    # ordinary hardware degradation is the Security State check's job (see
    # detection.security_state / teleportation_error_rate). If we
    # calibrated only against clean-hardware, single-basis sessions, the
    # Threat Detector would become oversensitive to conditions it will
    # actually see in production (degraded noise, X-basis sessions),
    # making the WEAK posture unreachable and/or inflating false positives
    # whenever a session happens to land on X-basis.
    honest_devs = []
    for noise_model in [DEFAULT_NOISE_MODEL, DEGRADED_NOISE_MODEL]:
        for basis in BASES:
            expected = stable_expected_distribution(MESSAGE_STATE, noise_model=noise_model, basis=basis)
            for _ in range(N_TRIALS // 4):
                observed = run_session(MESSAGE_STATE, attack_fn=None, shots=SHOTS_PER_TRIAL,
                                        noise_model=noise_model, basis=basis)
                honest_devs.append(chi_squared_deviation(observed, expected))

    attacked_devs = {}
    for name, fn in ATTACKS.items():
        if name == "none":
            continue
        devs = []
        for basis in BASES:
            expected = stable_expected_distribution(MESSAGE_STATE, basis=basis)
            for _ in range(N_TRIALS // 2):
                observed = run_session(MESSAGE_STATE, attack_fn=fn, shots=SHOTS_PER_TRIAL, basis=basis)
                devs.append(chi_squared_deviation(observed, expected))
        attacked_devs[name] = devs

    threshold = calibrate_threshold(honest_devs, sum(attacked_devs.values(), []), target_fpr=0.05)

    print(f"Honest deviation:  mean={np.mean(honest_devs):.4f}  std={np.std(honest_devs):.4f}")
    for name, devs in attacked_devs.items():
        print(f"{name:>22} deviation: mean={np.mean(devs):.4f}  std={np.std(devs):.4f}")

    print(f"\nCalibrated threshold (5% target FPR): {threshold:.4f}")
    print("Hardcode this value into app.py as CALIBRATED_THRESHOLD.")

    # quick sanity check: detection rate per attack type at this threshold
    print("\nDetection rate per attack type at this threshold:")
    for name, devs in attacked_devs.items():
        detected = np.mean(np.array(devs) >= threshold)
        print(f"{name:>22}: {detected * 100:.1f}%")

    fpr = np.mean(np.array(honest_devs) >= threshold)
    print(f"\nFalse positive rate on honest sessions: {fpr * 100:.1f}%")


if __name__ == "__main__":
    main()
