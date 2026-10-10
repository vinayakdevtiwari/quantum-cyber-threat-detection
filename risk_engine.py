"""
risk_engine.py
Combines the two INDEPENDENT evidence sources from your architecture
diagram into a single risk posture:

  Security State  (are the protocol's own assumptions satisfied?)
       +
  Threat Evidence (does this session look actively attacked?)
       =
  Security Posture

This is deliberately not a single score -- it's a 2x2 decision matrix,
because "secure but under attack" and "insecure but no attacker present"
are meaningfully different situations that a single number would blur
together.
"""

POSTURE_MATRIX = {
    ("SECURE", "NO_THREAT"): "VERY STRONG",
    ("SECURE", "THREAT"): "STRONG + ALERT",
    ("INSECURE", "NO_THREAT"): "WEAK",
    ("INSECURE", "THREAT"): "CRITICAL",
}


def compute_posture(security: str, threat: str):
    """
    security: "SECURE" or "INSECURE"      (from detection.security_state)
    threat:   "NO_THREAT" or "THREAT"     (derived from detection.verdict)
    """
    key = (security.upper(), threat.upper())
    if key not in POSTURE_MATRIX:
        raise ValueError(f"Unrecognized combination: {key}")
    return POSTURE_MATRIX[key]


def posture_explanation(posture: str):
    """Short, judge-friendly explanation of what each posture means."""
    explanations = {
        "VERY STRONG": "Assumptions hold and no attack detected. Normal healthy session.",
        "STRONG + ALERT": "Assumptions hold, but an attack is being attempted. "
                           "The protocol's guarantees are protecting this session -- "
                           "investigate the source, but the session itself is not compromised.",
        "WEAK": "No attack detected, but the protocol's own error-rate assumptions "
                "are violated. Security guarantees cannot be relied on even though "
                "nothing looks actively hostile yet -- treat as a latent risk.",
        "CRITICAL": "Assumptions violated AND an attack is being attempted. "
                    "Highest-risk state: the protocol's guarantees cannot be trusted "
                    "while it is also under active attack.",
    }
    return explanations[posture]
