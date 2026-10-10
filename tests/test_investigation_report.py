"""
tests/test_investigation_report.py

Tests for InvestigationReport model:
- Schema validation
- Plain-language report generation
- Technical report generation
- Blind-test ground-truth confidentiality protection
- Missing simulation results handling
"""

import pytest
from models.investigation_report import InvestigationReport, SourceLink


def sample_session_data(is_blind: bool = False, revealed: bool = False):
    return {
        "message_state": "1",
        "session_basis": "Z",
        "shots": 512,
        "deviation": 0.0425,
        "calibrated_threshold": 0.0253,
        "score": 1.68,
        "result": "ANOMALOUS - FLAG/REJECT",
        "threat_label": "THREAT",
        "error_rate": 0.145,
        "error_threshold": 0.11,
        "sec_state": "INSECURE",
        "posture": "CRITICAL",
        "explanation": "Assumptions violated AND an attack is being attempted.",
        "blind": is_blind,
        "revealed": revealed,
        "actual_attack": "forgery",
        "actual_channel": "Normal",
    }


def test_report_creation_and_validation():
    """Verify valid report creation passes validation with 0 errors."""
    data = sample_session_data(is_blind=False)
    report = InvestigationReport.create_from_session(data, calibrated_threshold=0.0253)

    assert report.report_id is not None
    assert report.risk_posture == "CRITICAL"
    assert report.threat_score == 1.68
    assert report.statistical_deviation == 0.0425
    assert report.actual_attack == "forgery"
    assert report.actual_channel == "Normal"

    errors = report.validate()
    assert errors == []


def test_plain_language_report_generation():
    """Verify plain summary contains human-readable explanation and no fabricated metrics."""
    data = sample_session_data(is_blind=False)
    report = InvestigationReport.create_from_session(data, calibrated_threshold=0.0253)

    assert "message qubit state '1'" in report.plain_summary
    assert "Z-basis" in report.plain_summary
    assert "512" in report.plain_summary
    assert "14.5%" in report.plain_summary
    assert "CRITICAL" in report.plain_summary
    # Ensure it doesn't declare a confirmed cyberattack
    assert "confirmed cyberattack" not in report.plain_summary.lower()


def test_technical_report_generation():
    """Verify technical explanation contains chi-squared and QBER context."""
    data = sample_session_data(is_blind=False)
    report = InvestigationReport.create_from_session(data, calibrated_threshold=0.0253)

    assert "chi-squared" in report.technical_explanation.lower()
    assert "0.0253" in report.technical_explanation
    assert "14.50%" in report.technical_explanation
    assert len(report.simulation_evidence) >= 5
    assert len(report.recommended_checks) >= 3
    assert len(report.known_limitations) >= 3


def test_blind_test_confidentiality_protection_before_reveal():
    """Verify ground truth is strictly concealed in Blind test mode before reveal."""
    data = sample_session_data(is_blind=True, revealed=False)
    report = InvestigationReport.create_from_session(data, calibrated_threshold=0.0253)

    assert report.simulation_mode == "Blind test"
    assert report.ground_truth_revealed is False
    assert report.is_blind_unrevealed is True
    # Ground truth MUST be None
    assert report.actual_attack is None
    assert report.actual_channel is None

    # Check evidence strings don't leak attack name
    for ev in report.simulation_evidence:
        assert "forgery" not in ev.lower()

    # Validation must succeed with concealed fields
    assert report.validate() == []


def test_blind_test_disclosure_after_reveal():
    """Verify ground truth is disclosed only after explicit reveal action."""
    data = sample_session_data(is_blind=True, revealed=True)
    report = InvestigationReport.create_from_session(data, calibrated_threshold=0.0253)

    assert report.simulation_mode == "Blind test"
    assert report.ground_truth_revealed is True
    assert report.is_blind_unrevealed is False
    assert report.actual_attack == "forgery"
    assert report.actual_channel == "Normal"

    # Evidence should now include ground truth
    combined_ev = " ".join(report.simulation_evidence)
    assert "forgery" in combined_ev


def test_report_schema_validation_failures():
    """Verify validator flags invalid schema fields."""
    data = sample_session_data(is_blind=False)
    report = InvestigationReport.create_from_session(data, calibrated_threshold=0.0253)

    # Corrupt fields
    report.shot_count = -10
    report.error_rate = 1.8
    report.security_state = "INVALID_STATE"
    report.risk_posture = "SUPER_CRITICAL"
    report.research_status = "bogus_status"

    errors = report.validate()
    assert len(errors) == 5
    assert any("shot_count" in e for e in errors)
    assert any("error_rate" in e for e in errors)
    assert any("security_state" in e for e in errors)
    assert any("risk_posture" in e for e in errors)
    assert any("research_status" in e for e in errors)


def test_missing_simulation_results():
    """Verify report creation from empty dict handles missing keys with safe defaults."""
    empty_data = {}
    report = InvestigationReport.create_from_session(empty_data)
    assert report.report_id is not None
    assert report.shot_count > 0
    assert report.calibrated_threshold == 0.0253
    assert report.validate() == []
