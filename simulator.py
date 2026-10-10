"""
simulator.py
Simulates a single Quantum Digital Signature (QDS) session using a
teleportation-based protocol, built on Qiskit + AerSimulator.

  1. Prepare a "message" qubit in some state (the thing being "signed").
  2. Create an entangled pair (the shared resource between signer/verifier).
  3. Teleport the message qubit's state using the entangled pair.
  4. Apply Pauli correction based on the classical measurement bits.
  5. Return the final measurement outcomes -- this is the "observed distribution"
     your detection layer will statistically test.

An honest run (no attack) should reproduce the expected state reliably.
An attacked run (see attacks.py) perturbs this process, which shows up
as a shift in the measurement statistics.
"""

import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error

simulator = AerSimulator()


def build_noise_model(single_qubit_error: float = 0.001, two_qubit_error: float = 0.01):
    """
    Build a simple depolarizing noise model to stand in for real hardware
    imperfections, per the feasibility slide's "calibrate noise against
    published error rates" strategy.

    Defaults are in the ballpark of published superconducting-qubit error
    rates (~0.1% single-qubit gate error, ~1% two-qubit gate error) -- cite
    this range if asked, and feel free to tune it against a specific paper
    you reference on your slides.
    """
    noise_model = NoiseModel()

    error_1q = depolarizing_error(single_qubit_error, 1)
    noise_model.add_all_qubit_quantum_error(error_1q, ["x", "h", "rx", "z"])

    error_2q = depolarizing_error(two_qubit_error, 2)
    noise_model.add_all_qubit_quantum_error(error_2q, ["cx", "cz"])

    return noise_model


# Built once at import time; expected_counts() and run_session() both use
# this by default so honest and attacked sessions are compared on equal,
# realistic footing rather than one being noiseless.
DEFAULT_NOISE_MODEL = build_noise_model()

# A second, noisier model representing channel/hardware degradation with
# NO attacker present -- lets the demo show the WEAK quadrant (insecure
# assumptions, but nothing actively hostile detected).
DEGRADED_NOISE_MODEL = build_noise_model(single_qubit_error=0.02, two_qubit_error=0.09)


def build_teleportation_circuit(message_state: str = "1", attack_fn=None, basis: str = "Z"):
    qc = QuantumCircuit(3, 3)

    # prepare the message qubit, in the chosen basis
    if basis == "Z":
        if message_state == "1":
            qc.x(0)
    else:  # basis == "X"
        qc.h(0)
        if message_state == "1":
            qc.z(0)
    qc.barrier()

    qc.h(1)
    qc.cx(1, 2)
    qc.barrier()

    if attack_fn is not None:
        qc = attack_fn(qc)

    qc.cx(0, 1)
    qc.h(0)
    qc.barrier()
    qc.measure([0, 1], [0, 1])
    qc.barrier()

    qc.cx(1, 2)
    qc.cz(0, 2)

    if basis == "X":
        qc.h(2)   # rotate back before measuring, so X-basis errors show up as bit-flips
    qc.measure(2, 2)

    return qc


def run_session(message_state: str = "1", attack_fn=None, shots: int = 1024,
                 noise_model=DEFAULT_NOISE_MODEL, basis: str = "Z"):
    """
    Run one QDS session `shots` times and return the raw measurement counts.
    Repeating the shots is what lets the detection layer build a distribution
    to test statistically -- a single shot tells you almost nothing.

    noise_model: pass None for a noiseless (ideal) simulation, e.g. for
    quick debugging. Defaults to DEFAULT_NOISE_MODEL so honest and attacked
    sessions are both evaluated under the same realistic conditions.
    """
    qc = build_teleportation_circuit(message_state, attack_fn, basis)
    job = simulator.run(qc, shots=shots, noise_model=noise_model)
    result = job.result()
    counts = result.get_counts()
    return counts


def expected_counts(message_state: str = "1", shots: int = 1024,
                     noise_model=DEFAULT_NOISE_MODEL, basis: str = "Z"):
    """
    Ground-truth distribution for an honest session with no attack (but
    WITH the same realistic noise as any other session) -- used as the
    'expected distribution' the detection layer compares against. Using
    the same noise model here as in run_session is important: otherwise
    ordinary hardware noise alone would look like an attack.
    """
    return run_session(message_state=message_state, attack_fn=None, shots=shots,
                        noise_model=noise_model, basis=basis)


# IMPORTANT: the "expected distribution" needs to be a STABLE reference,
# not a fresh small random sample every time. With few shots, rare
# outcomes get only a handful of counts, and comparing two independently
# noisy samples against each other makes the deviation statistic wildly
# unstable -- honest sessions can spuriously look "anomalous" just from
# baseline sampling noise. We fix this by computing the expected
# distribution once, with many more shots, and reusing it as a constant
# reference for every comparison in a given run.
_REFERENCE_SHOTS = 8192
_reference_cache = {}


def stable_expected_distribution(message_state: str = "1", noise_model=DEFAULT_NOISE_MODEL, basis: str = "Z"):
    """
    Returns a cached, high-shot expected measurement distribution for the
    given message state. Computed once per process and reused everywhere,
    so every session (honest or attacked) is judged against the same
    stable baseline.
    """
    key = (message_state, basis, id(noise_model))
    if key not in _reference_cache:
        counts = run_session(message_state, attack_fn=None, shots=_REFERENCE_SHOTS,
                              noise_model=noise_model, basis=basis)
        _reference_cache[key] = counts
    return _reference_cache[key]


if __name__ == "__main__":
    print("Honest session (message='1'), with realistic noise:")
    print(run_session("1"))
    print("\nHonest session (message='1'), ideal/noiseless:")
    print(run_session("1", noise_model=None))
