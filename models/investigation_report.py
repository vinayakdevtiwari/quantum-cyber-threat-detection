"""
models/investigation_report.py

Validated investigation report schema and domain model for Q-Intel AI agent.
Provides structured storage, strict validation, and blind-test confidentiality protection.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone


@dataclass
class SourceLink:
    title: str
    url: str
    snippet: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationReport:
    # Identity
    report_id: str
    timestamp_utc: str

    # Session configuration
    simulation_mode: str  # 'Manual' or 'Blind test'
    message_state: str  # '0' or '1'
    measurement_basis: str  # 'Z' or 'X'
    shot_count: int

    # Detector output
    detector_verdict: str  # e.g., 'ANOMALOUS - FLAG/REJECT' or 'NORMAL - ACCEPT'
    statistical_deviation: float
    calibrated_threshold: float
    threat_score: float
    threat_label: str  # 'THREAT' or 'NO_THREAT'

    # Security state
    error_rate: float
    error_threshold: float
    security_state: str  # 'SECURE' or 'INSECURE'

    # Risk engine
    risk_posture: str  # 'VERY STRONG', 'STRONG + ALERT', 'WEAK', 'CRITICAL'
    posture_explanation: str

    # Analysis content
    plain_summary: str
    technical_explanation: str
    simulation_evidence: List[str]
    external_research: List[str]
    recommended_checks: List[str]
    known_limitations: List[str]

    # Research metadata
    research_status: str  # 'pending', 'completed', 'unavailable', 'not_configured', 'error'
    source_links: List[SourceLink] = field(default_factory=list)

    # Blind test protection
    ground_truth_revealed: bool = False
    actual_attack: Optional[str] = None
    actual_channel: Optional[str] = None

    # Two-device (phone demo) incident fields. Optional so dashboard-session
    # reports keep their existing shape; populated by
    # create_from_phone_session and rendered into the email's Attack Overview.
    session_code: Optional[str] = None
    original_message: Optional[str] = None
    received_message: Optional[str] = None
    attack_type: Optional[str] = None
    attack_description: Optional[str] = None
    attacked_bits_display: Optional[str] = None
    bit_verdict: Optional[str] = None
    witness: Optional[Dict[str, Any]] = None

    @classmethod
    def create_from_session(cls, session_data: Dict[str, Any], calibrated_threshold: float = 0.0253) -> 'InvestigationReport':
        """
        Creates an InvestigationReport from session output dictionary.
        Supports both app.py's last_run format and normalized dictionary keys.
        Preserves strict blind-test confidentiality: never exposes actual_attack or actual_channel
        if in Blind test mode unless ground_truth_revealed is explicitly True.
        """
        report_id = str(uuid.uuid4())
        timestamp_utc = datetime.now(timezone.utc).isoformat()

        # Handle simulation mode
        if "blind" in session_data:
            sim_mode = "Blind test" if session_data["blind"] else "Manual"
        else:
            sim_mode = session_data.get("simulation_mode", "Manual")

        is_blind = sim_mode == "Blind test"
        revealed = bool(session_data.get("revealed", session_data.get("ground_truth_revealed", False)))

        # Ground truth protection
        if is_blind and not revealed:
            actual_attack = None
            actual_channel = None
        else:
            actual_attack = session_data.get("actual_attack")
            actual_channel = session_data.get("actual_channel")

        # Session params
        msg_state = str(session_data.get("message_state", "1"))
        basis = str(session_data.get("session_basis", session_data.get("measurement_basis", "Z")))
        shots = int(session_data.get("shots", session_data.get("shot_count", 512)))

        # Detector values
        dev = float(session_data.get("deviation", session_data.get("statistical_deviation", 0.0)))
        thresh = float(session_data.get("calibrated_threshold", calibrated_threshold))
        score = float(session_data.get("score", session_data.get("threat_score", 0.0)))
        verdict = str(session_data.get("result", session_data.get("detector_verdict", "NORMAL - ACCEPT")))
        threat_label = str(session_data.get("threat_label", "NO_THREAT" if "NORMAL" in verdict else "THREAT"))

        # Security state
        err_rate = float(session_data.get("error_rate", 0.0))
        err_thresh = float(session_data.get("error_threshold", 0.11))
        sec_state = str(session_data.get("sec_state", session_data.get("security_state", "SECURE")))

        # Risk engine
        posture = str(session_data.get("posture", session_data.get("risk_posture", "VERY STRONG")))
        explanation = str(session_data.get("explanation", session_data.get("posture_explanation", "")))

        # Build initial plain summary
        sig_dev = "no significant" if dev <= thresh else "a statistically significant"
        within_above = "within" if err_rate <= err_thresh else "above"
        plain_summary = (
            f"This simulated QDS session encoded message qubit state '{msg_state}' and performed verification in the {basis}-basis across {shots} execution shots. "
            f"The statistical anomaly detector observed a chi-squared divergence of {dev:.4f} against the honest baseline ({sig_dev} deviation relative to threshold {thresh:.4f}). "
            f"The teleported-bit error rate was measured at {err_rate * 100:.1f}%, which is {within_above} the acceptable protocol security threshold of {err_thresh * 100:.0f}%. "
            f"Synthesizing these dual checks, the Risk Engine assigned a security posture of {posture}."
        )

        tech_expl = (
            f"Session telemetry evaluates two decoupled verification layers: "
            f"(1) Security State evaluates physical verification fidelity by testing whether clbit 2 matches the prepared state '{msg_state}'. "
            f"The measured error rate of {err_rate * 100:.2f}% evaluates whether the teleportation channel operates within the theoretical QBER bound ({err_thresh * 100:.1f}%). "
            f"(2) Threat Detector performs a Pearson chi-squared distributional divergence test across all 3-qubit basis states (observed vs. 8192-shot calibrated honest reference). "
            f"The resulting score of {score:.2f} (deviation {dev:.4f} / threshold {thresh:.4f}) determined the statistical verdict '{verdict}'. "
            f"Final Risk Posture '{posture}' was derived via the 2x2 posture decision matrix combining Security State ({sec_state}) and Threat Evidence ({threat_label})."
        )

        simulation_evidence = [
            f"Measurement Basis: {basis}-basis | Message State: |{msg_state}>",
            f"Total Shot Count: {shots} Monte Carlo shots",
            f"Statistical Deviation: {dev:.4f} (Calibrated Threshold: {thresh:.4f})",
            f"Normalized Threat Score: {score:.2f} ({'exceeds' if score >= 1.0 else 'within'} gate 1.0)",
            f"Detector Verdict: {verdict}",
            f"Teleportation Error Rate: {err_rate * 100:.2f}% (Security Threshold: {err_thresh * 100:.0f}%)",
            f"Security State: {sec_state}",
            f"Risk Engine Posture: {posture} ({explanation})"
        ]

        if not is_blind or revealed:
            if actual_attack:
                simulation_evidence.append(f"Ground Truth Attack Injection: {actual_attack}")
            if actual_channel:
                simulation_evidence.append(f"Ground Truth Channel Condition: {actual_channel}")

        recommended_checks = [
            "Re-run verification across orthogonal bases (alternate between Z and X bases) to confirm whether anomalies persist across complementary Pauli observables.",
            "Compare session error rates against an honest calibration pool acquired under identical hardware noise characteristics.",
            "Verify whether the current threat score delta reflects genuine channel perturbation or finite-sampling variance given the configured shot count.",
            "Audit classical communication channels and Bell-state measurement feedforward logic for unauthorized delays or tampering."
        ]

        known_limitations = [
            "Simulation Sandbox: Results are generated using Qiskit Aer depolarizing noise simulation, not physical quantum hardware (no thermal relaxation, readout crosstalk, or drift).",
            "Threshold Specificity: The statistical threshold was calibrated offline for this specific simulated circuit topology and shot profile.",
            "Prototype Protocol: Simplified 3-qubit teleportation scheme serves as an educational model; full QDS requires multiport optical interferometers and multi-party Byzantine consensus.",
            "Representative Bounds: The 11% error threshold is an illustrative QBER analog modeled on BB84 bounds, not an analytic security proof for this specific scheme."
        ]

        return cls(
            report_id=report_id,
            timestamp_utc=timestamp_utc,
            simulation_mode=sim_mode,
            message_state=msg_state,
            measurement_basis=basis,
            shot_count=shots,
            detector_verdict=verdict,
            statistical_deviation=dev,
            calibrated_threshold=thresh,
            threat_score=score,
            threat_label=threat_label,
            error_rate=err_rate,
            error_threshold=err_thresh,
            security_state=sec_state,
            risk_posture=posture,
            posture_explanation=explanation,
            plain_summary=plain_summary,
            technical_explanation=tech_expl,
            simulation_evidence=simulation_evidence,
            external_research=[],
            recommended_checks=recommended_checks,
            known_limitations=known_limitations,
            research_status="not_configured",
            source_links=[],
            ground_truth_revealed=revealed,
            actual_attack=actual_attack,
            actual_channel=actual_channel,
        )

    # Alias for convenience
    from_session = create_from_session

    @classmethod
    def create_from_phone_session(cls, session_data: Dict[str, Any]) -> 'InvestigationReport':
        """
        Build a report for a two-device (phone demo) incident.

        Kept separate from create_from_session because the two describe
        different measurements. A dashboard session reports a chi-squared
        divergence for a single teleported qubit; a phone session reports
        per-bit integrity for a whole message register. Reusing the single-qubit
        summary text would state things about chi-squared values that this
        session never computed.

        The pose in this report is therefore per-bit integrity mapped onto the
        same 2x2 posture matrix, and the deviation fields stay at zero with the
        limitation recorded rather than estimated.
        """
        import uuid
        from datetime import datetime, timezone

        total_bits = session_data.get("total_bits", 0)
        corrupted = session_data.get("corrupted_bits", 0)
        err_rate = float(session_data.get("error_rate", 0.0))
        posture = session_data.get("posture", "VERY STRONG")
        explanation = session_data.get("explanation", "")
        attack = session_data.get("attack_type") or "none (honest channel)"
        verdict = session_data.get("bit_verdict", "AWAITING ATTACK")
        witness_data = session_data.get("witness") or {}

        plain_summary = (
            f"A two-device demo session ({session_data.get('session_code')}) "
            f"transmitted the message \"{session_data.get('original_message')}\" "
            f"over a simulated quantum channel, one qubit per bit "
            f"({total_bits} bits, {total_bits * 3} qubits). "
            f"The receiver decoded \"{session_data.get('received_message')}\" and "
            f"found {corrupted} of {total_bits} bits corrupted "
            f"({err_rate * 100:.2f}% bit error rate), a message-layer verdict of "
            f"{verdict}. An attack of type '{attack}' was "
            f"{'injected into the channel' if session_data.get('attack_type') else 'not present'}. "
            f"Mapping that integrity result onto the Security State / Threat "
            f"Detector matrix yields a risk posture of {posture}."
        )

        tech_expl = (
            f"Origin: two-device phone demo, session {session_data.get('session_code')}, "
            f"captured {session_data.get('created_utc')}. "
            f"The message was encoded as ASCII, one qubit per bit, and each bit was "
            f"teleported through a 3-qubit protocol (Bell measurement plus conditional "
            f"Pauli correction) under a Qiskit Aer depolarizing noise model. "
            f"Attack mechanism: {session_data.get('attack_description') or 'none'}. "
            f"Bit-level integrity check: {corrupted}/{total_bits} bits differ from the "
            f"signed original, giving a {err_rate * 100:.2f}% error rate against an "
            f"{err_rate and session_data.get('error_threshold', 0.11) * 100:.0f}% "
            f"tolerance -> Security State {session_data.get('sec_state')}. "
            f"Threat Detector mapped to {session_data.get('threat_label')} because an "
            f"attack was present. Risk Posture '{posture}' follows from the 2x2 matrix. "
            f"NOTE: no chi-squared divergence is reported for this session; it was "
            f"verified per-bit rather than distributionally."
        )

        # A replayed signature PASSES every quantum check and is caught purely
        # by context. That combination is the most interesting thing this report
        # can say, so it is surfaced in the summary rather than buried.
        if witness_data.get("verdict") == "REPLAY BLOCKED":
            plain_summary += (
                " Notably, the quantum witness ACCEPTED this signature, because it "
                "is genuine. Replay was detected solely by the context binding, "
                "which found the signature belonged to an earlier session. "
                "Quantum unforgeability and replay resistance are separate "
                "properties, and this incident shows why context binding is "
                "required alongside the quantum layer."
            )

        return cls(
            report_id=str(uuid.uuid4()),
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            simulation_mode="Phone demo (two-device)",
            message_state="n/a (multi-bit message register)",
            measurement_basis="Z",
            shot_count=int(session_data.get("shots", 256)),
            detector_verdict=str(session_data.get("result", "ANOMALOUS - FLAG/REJECT")),
            statistical_deviation=0.0,
            calibrated_threshold=0.0253,
            threat_score=0.0,
            threat_label=str(session_data.get("threat_label", "THREAT")),
            error_rate=err_rate,
            error_threshold=float(session_data.get("error_threshold", 0.11)),
            security_state=str(session_data.get("sec_state", "SECURE")),
            risk_posture=posture,
            posture_explanation=explanation,
            plain_summary=plain_summary,
            technical_explanation=tech_expl,
            simulation_evidence=session_data.get("simulation_evidence", []),
            external_research=[],
            recommended_checks=[
                "Confirm the per-bit integrity failures against the sender's held witness state; a keyless forger cannot reproduce the correct pattern in both bases.",
                "Re-verify the message on an orthogonal measurement basis to distinguish bit-flip (X) from phase (Z) errors.",
                "Audit the channel between the two devices for any relay or man-in-the-middle that could have injected the observed corruption.",
                "Establish whether the attack was targeted at specific bit positions, which would suggest a forgery attempt rather than random channel noise.",
            ],
            known_limitations=session_data.get("known_limitations", []),
            research_status="not_configured",
            source_links=[],
            ground_truth_revealed=True,
            actual_attack=session_data.get("actual_attack"),
            actual_channel=session_data.get("actual_channel"),
            # Two-device incident fields, carried through to the email template
            # so the Attack Overview section can render the signed/received
            # pair and the exact corrupted bit indices.
            session_code=session_data.get("session_code"),
            original_message=session_data.get("original_message"),
            received_message=session_data.get("received_message"),
            attack_type=session_data.get("attack_type"),
            attack_description=session_data.get("attack_description"),
            attacked_bits_display=session_data.get("attacked_bits_display"),
            bit_verdict=session_data.get("bit_verdict"),
            witness=session_data.get("witness"),
        )

    def validate(self) -> List[str]:
        """Validates all schema fields. Returns list of validation error descriptions."""
        errors: List[str] = []

        if not self.report_id:
            errors.append("report_id is required")
        if not self.timestamp_utc:
            errors.append("timestamp_utc is required")

        # "Phone demo (two-device)" covers incidents generated by the second
        # device in the two-device bit-manipulation demo, which report
        # per-bit integrity rather than a single teleported-qubit check.
        if self.simulation_mode not in ("Manual", "Blind test", "Phone demo (two-device)"):
            errors.append(f"Invalid simulation_mode: {self.simulation_mode}")

        # Phone-demo sessions carry a multi-bit message register rather than a
        # single qubit state, so a descriptive placeholder is valid here.
        if self.message_state not in ("0", "1") and not self.message_state.startswith("n/a"):
            errors.append(f"Invalid message_state: {self.message_state}")

        if self.measurement_basis not in ("Z", "X"):
            errors.append(f"Invalid measurement_basis: {self.measurement_basis}")

        if self.shot_count <= 0:
            errors.append(f"shot_count must be > 0 (got {self.shot_count})")

        if self.statistical_deviation < 0.0:
            errors.append("statistical_deviation must be non-negative")

        if self.calibrated_threshold <= 0.0:
            errors.append("calibrated_threshold must be strictly positive")

        if self.threat_score < 0.0:
            errors.append("threat_score must be non-negative")

        if self.error_rate < 0.0 or self.error_rate > 1.0:
            errors.append(f"error_rate must be in [0.0, 1.0] (got {self.error_rate})")

        if self.security_state not in ("SECURE", "INSECURE"):
            errors.append(f"Invalid security_state: {self.security_state}")

        if self.threat_label not in ("THREAT", "NO_THREAT"):
            errors.append(f"Invalid threat_label: {self.threat_label}")

        valid_postures = ("VERY STRONG", "STRONG + ALERT", "WEAK", "CRITICAL")
        if self.risk_posture not in valid_postures:
            errors.append(f"Invalid risk_posture: {self.risk_posture}")

        valid_statuses = ("pending", "completed", "unavailable", "not_configured", "error")
        if self.research_status not in valid_statuses:
            errors.append(f"Invalid research_status: {self.research_status}")

        # Blind test confidentiality validation
        if self.simulation_mode == "Blind test" and not self.ground_truth_revealed:
            if self.actual_attack is not None:
                errors.append("actual_attack must be None when blind test ground truth is unrevealed")
            if self.actual_channel is not None:
                errors.append("actual_channel must be None when blind test ground truth is unrevealed")

        return errors

    @property
    def is_blind_unrevealed(self) -> bool:
        """True if running in Blind test mode and ground truth has not been revealed."""
        return self.simulation_mode == "Blind test" and not self.ground_truth_revealed

    def update_research(self, external_findings: List[str], sources: List[SourceLink], status: str) -> None:
        """Update the report with external research findings."""
        self.external_research = external_findings
        self.source_links = sources
        self.research_status = status

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary with serialized source links."""
        data = asdict(self)
        data["source_links"] = [link.to_dict() if hasattr(link, "to_dict") else link for link in self.source_links]
        return data
