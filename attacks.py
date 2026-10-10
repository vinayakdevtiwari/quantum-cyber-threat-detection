"""
attacks.py
Simplified single-gate attack injectors for the teleportation-based QDS
session. Each callable mutates the circuit mid-protocol (after entanglement,
before Bell measurement) and returns it.

These are demonstration models, not full adversarial protocol deviations.
`channel_manipulation` is randomized (50/50 X or Z on Bob's qubit), so it
will not trigger detection on every run.
"""

import numpy as np


def none_attack(qc):
    """Honest session — no circuit mutation."""
    return qc


def forgery_attack(qc):
    """Forgery: flip the message qubit to spoof the signed state."""
    qc.x(0)
    return qc


def impersonation_attack(qc):
    """Impersonation: phase-tamper Alice's half of the entangled pair."""
    qc.z(1)
    return qc


def replay_attack(qc):
    """Replay: bit-flip Bob's entangled qubit before teleportation completes."""
    qc.x(2)
    return qc


def channel_manipulation_attack(qc):
    """Channel manipulation: random X or Z on the quantum channel (qubit 2)."""
    if np.random.rand() < 0.5:
        qc.x(2)
    else:
        qc.z(2)
    return qc


ATTACKS = {
    "none": none_attack,
    "forgery": forgery_attack,
    "impersonation": impersonation_attack,
    "replay": replay_attack,
    "channel_manipulation": channel_manipulation_attack,
}
