"""
tests/test_email_service.py

Automated tests for transactional email reporting service (Resend API):
- Valid and invalid recipient email validation
- Email HTML escaping and XSS safety
- Email plain-text alternative fallback
- Missing email-provider configuration handling
- Failed email delivery (mock HTTP error)
- Successful email delivery (mock HTTP 200 with ID)
- Prototype disclaimers and styling integrity
"""

import json
import io
import urllib.error
from unittest.mock import patch, MagicMock
import pytest

from services.email_service import (
    EmailService,
    validate_email,
    build_report_email_html,
    EmailSendResult,
)


def test_email_address_validation():
    """Verify email address format validator."""
    assert validate_email("analyst@example.com") is True
    assert validate_email("sec-team+alerts@corp.co.uk") is True
    assert validate_email("vinayak@team.org") is True

    # Invalid cases
    assert validate_email("") is False
    assert validate_email("plainaddress") is False
    assert validate_email("missingdomain@") is False
    assert validate_email("@missinguser.com") is False
    assert validate_email("spaces in@email.com") is False
    assert validate_email(None) is False


def test_email_html_escaping_prevents_xss():
    """Verify dangerous script tags in dynamic fields are safely HTML-escaped."""
    malicious_report = {
        "report_id": "<script>alert('xss')</script>",
        "timestamp_utc": "2026-10-10",
        "risk_posture": "<img src=x onerror=alert(1)>",
        "plain_summary": "Test summary with <script>evil()</script>",
        "simulation_evidence": ["<b>Bold</b>", "<script>steal()</script>"],
        "recommended_checks": ["<iframe src='malicious.site'></iframe>"],
    }

    html_body, text_body = build_report_email_html(malicious_report, style="simple")

    # Script/iframe tags MUST be escaped in HTML
    assert "<script>" not in html_body
    assert ("&lt;script&gt;alert('xss')&lt;/script&gt;" in html_body or
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_body)
    assert "<iframe" not in html_body
    assert ("&lt;iframe src='malicious.site'&gt;&lt;/iframe&gt;" in html_body or
            "&lt;iframe src=&#x27;malicious.site&#x27;&gt;&lt;/iframe&gt;" in html_body)
    assert "<img" not in html_body
    assert "&lt;img" in html_body


def test_email_plain_text_fallback():
    """Verify plain-text alternative contains core metadata and disclaimer."""
    report = {
        "report_id": "test-uuid-1234",
        "timestamp_utc": "2026-10-10 12:00:00 UTC",
        "risk_posture": "VERY STRONG",
        "simulation_mode": "Manual",
        "measurement_basis": "Z",
        "shot_count": 512,
        "plain_summary": "Nominal verification session.",
        "recommended_checks": ["Audit log verification", "Noise pool comparison"],
        "known_limitations": ["Circuit simulation only"],
    }

    html_body, text_body = build_report_email_html(report, style="simple")

    assert "QUANTUM CYBER THREAT DETECTION" in text_body
    assert "test-uuid-1234" in text_body
    assert "VERY STRONG" in text_body
    assert "Nominal verification session." in text_body
    assert "Audit log verification" in text_body
    assert "DISCLAIMER" in text_body


def test_missing_email_configuration():
    """Verify send_report returns clean error when RESEND_API_KEY is not configured."""
    with patch.dict("os.environ", {}, clear=True):
        service = EmailService(api_key=None)
        assert service.is_configured is False

        res = service.send_report(
            recipient="test@example.com",
            subject="Test Subject",
            html_body="<p>Test</p>",
            text_body="Test",
        )
        assert res.success is False
        assert "not configured" in res.error_message.lower()


def test_invalid_recipient_returns_error():
    """Verify invalid recipient email is rejected before making any network call."""
    service = EmailService(api_key="re_test_key_123")
    with patch("urllib.request.urlopen") as mock_url:
        res = service.send_report(
            recipient="not-an-email",
            subject="Test Subject",
            html_body="<p>Test</p>",
            text_body="Test",
        )
        assert res.success is False
        assert "Validation error" in res.error_message
        assert mock_url.call_count == 0


def test_successful_email_delivery():
    """Verify successful send parses provider message ID."""
    service = EmailService(api_key="re_test_key_123", from_email="QCTD <reports@test.com>")
    fake_response = {"id": "msg_9988776655"}

    resp = MagicMock()
    resp.read.return_value = json.dumps(fake_response).encode("utf-8")
    resp.getcode.return_value = 200
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = None

    with patch("urllib.request.urlopen", return_value=resp):
        res = service.send_report(
            recipient="analyst@soc.org",
            subject="QCTD Alert",
            html_body="<p>Alert Body</p>",
            text_body="Alert Body",
        )
        assert res.success is True
        assert res.message_id == "msg_9988776655"
        assert res.error_message is None


def test_failed_email_delivery_http_error():
    """Verify HTTP error from provider is captured safely without exposing credentials."""
    service = EmailService(api_key="re_test_key_123")
    http_error = urllib.error.HTTPError(
        url="https://api.resend.com/emails",
        code=422,
        msg="Unprocessable Entity",
        hdrs={},
        fp=io.BytesIO(b'{"message": "Domain is not verified"}')
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        res = service.send_report(
            recipient="analyst@soc.org",
            subject="QCTD Alert",
            html_body="<p>Alert Body</p>",
            text_body="Alert Body",
        )
        assert res.success is False
        assert "Domain is not verified" in res.error_message
        # Confirm API key is never in error message
        assert "re_test_key" not in res.error_message
