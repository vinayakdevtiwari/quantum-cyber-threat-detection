"""
tests/test_report_service.py

Tests for QIntelAgent investigation workflow:
- Full session investigation with mock TinyFish search and fetch
- Investigation without live research when TinyFish is unconfigured (offline fallback)
- Investigation with empty/missing simulation results
- Verifying report generation alone does NOT trigger email sending
- Preventing accidental duplicate sends
- Deep research execution
"""

from unittest.mock import MagicMock
import pytest

from models.investigation_report import InvestigationReport, SourceLink
from services.report_service import QIntelAgent
from services.tinyfish_client import (
    TinyFishClient,
    SearchResult,
    SearchResultItem,
    FetchResult,
    FetchResultItem,
    ResearchResult,
    ResearchSource,
)
from services.email_service import EmailService, EmailSendResult


def sample_session_output():
    return {
        "message_state": "1",
        "session_basis": "Z",
        "shots": 512,
        "deviation": 0.0380,
        "calibrated_threshold": 0.0253,
        "score": 1.50,
        "result": "ANOMALOUS - FLAG/REJECT",
        "threat_label": "THREAT",
        "error_rate": 0.04,
        "error_threshold": 0.11,
        "sec_state": "SECURE",
        "posture": "STRONG + ALERT",
        "explanation": "Assumptions hold, but an attack is being attempted.",
        "blind": False,
        "revealed": True,
        "actual_attack": "impersonation",
        "actual_channel": "Normal",
    }


def test_investigate_session_with_mock_tinyfish():
    """Verify Q-Intel integrates search results and citations into investigation report."""
    mock_tf = MagicMock(spec=TinyFishClient)
    mock_tf.is_configured = True
    mock_tf.search.return_value = SearchResult(
        items=[
            SearchResultItem(
                title="QDS Security Proofs and Eavesdropping",
                url="https://quantum-journal.org/papers/qds-proof",
                snippet="Phase-flip attacks in Bell teleportation remain detectable in complementary bases.",
            )
        ],
        query="test query",
    )
    mock_tf.fetch_urls.return_value = FetchResult(
        items=[
            FetchResultItem(
                url="https://quantum-journal.org/papers/qds-proof",
                title="QDS Security Proofs and Eavesdropping",
                content="Full paper text analyzing teleportation-based QDS security and fidelity boundaries.",
                status="ok",
            )
        ],
        errors=[],
    )

    agent = QIntelAgent(tinyfish_client=mock_tf)
    session = sample_session_output()

    report = agent.investigate_session(session, calibrated_threshold=0.0253)

    assert isinstance(report, InvestigationReport)
    assert report.risk_posture == "STRONG + ALERT"
    assert report.research_status == "completed"
    assert len(report.source_links) >= 1
    assert report.source_links[0].title == "QDS Security Proofs and Eavesdropping"
    assert any("Phase-flip attacks" in f for f in report.external_research)
    assert mock_tf.search.call_count == 1


def test_investigate_session_offline_fallback():
    """Verify offline fallback when TinyFish is unconfigured."""
    mock_tf = MagicMock(spec=TinyFishClient)
    mock_tf.is_configured = False

    agent = QIntelAgent(tinyfish_client=mock_tf)
    session = sample_session_output()

    report = agent.investigate_session(session, calibrated_threshold=0.0253)

    assert report.research_status == "not_configured"
    assert mock_tf.search.call_count == 0
    # Must explicitly state in limitations that report was generated without live research
    assert any("without live external research" in lim for lim in report.known_limitations)


def test_investigate_session_missing_results():
    """Verify ValueError is raised if session_data is empty."""
    agent = QIntelAgent()
    with pytest.raises(ValueError):
        agent.investigate_session({})


def test_report_generation_does_not_send_email():
    """Verify creating a report or previewing email NEVER triggers send_report."""
    mock_email = MagicMock(spec=EmailService)
    mock_email.is_configured = True

    agent = QIntelAgent(email_service=mock_email)
    session = sample_session_output()

    # 1. Investigate
    report = agent.investigate_session(session)
    # 2. Generate content (preview)
    html_body, text_body = agent.generate_report_content(report, style="technical")

    # Email send MUST NOT have been called
    assert mock_email.send_report.call_count == 0
    assert "QUANTUM CYBER THREAT DETECTION" in text_body


def test_send_email_report_success_and_duplicate_handling():
    """Verify send_email_report invokes service and returns send result."""
    mock_email = MagicMock(spec=EmailService)
    mock_email.is_configured = True
    mock_email.send_report.return_value = EmailSendResult(success=True, message_id="msg_abc123")

    agent = QIntelAgent(email_service=mock_email)
    session = sample_session_output()
    report = agent.investigate_session(session)

    res = agent.send_email_report(report, recipient="analyst@enterprise.com", style="simple")

    assert res.success is True
    assert res.message_id == "msg_abc123"
    assert mock_email.send_report.call_count == 1

    # Verify recipient validation in send_email_report
    invalid_res = agent.send_email_report(report, recipient="bad-address", style="simple")
    assert invalid_res.success is False
    assert "Invalid recipient" in invalid_res.error_message
    assert mock_email.send_report.call_count == 1  # No additional send attempt


def test_deep_research_action():
    """Verify run_deep_research calls Agent API and updates report findings."""
    mock_tf = MagicMock(spec=TinyFishClient)
    mock_tf.is_configured = True
    mock_tf.run_deep_research.return_value = ResearchResult(
        run_id="run_deep_1",
        status="completed",
        report="Deep research confirms high-fidelity verification requires orthogonal basis pooling.",
        sources=[ResearchSource(title="Quantum Security Journal", url="https://qsj.org/paper")],
    )

    agent = QIntelAgent(tinyfish_client=mock_tf)
    session = sample_session_output()
    report = agent.investigate_session(session)

    updated_report = agent.run_deep_research(report, question="How does basis pooling protect against phase flip?")

    assert mock_tf.run_deep_research.call_count == 1
    assert any("Deep Research Synthesis:" in f for f in updated_report.external_research)
    assert any(s.title == "Quantum Security Journal" for s in updated_report.source_links)
