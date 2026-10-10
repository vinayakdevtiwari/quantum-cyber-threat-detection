"""
services/email_service.py

Transactional email delivery service using the Resend API (https://resend.com/docs/api-reference/emails/send-email).
Provides branded HTML/plain-text report generation with safe HTML escaping and mobile responsiveness.
"""

import os
import re
import json
import smtplib
import urllib.request
import urllib.error
import html
from email.message import EmailMessage
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, Any, List

# Load .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import streamlit as st
except ImportError:
    st = None


class EmailError(Exception):
    """Base class for email-related errors."""
    pass


class EmailNotConfiguredError(EmailError):
    """Raised when the Resend API key is missing."""
    pass


class EmailValidationError(EmailError):
    """Raised when the provided email address is invalid."""
    pass


class EmailDeliveryError(EmailError):
    """Raised when email delivery fails."""
    pass


@dataclass
class EmailSendResult:
    success: bool
    message_id: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "message_id": self.message_id,
            "error_message": self.error_message,
        }


def validate_email(address: str) -> bool:
    """Validates recipient email address format."""
    if not address or not isinstance(address, str):
        return False
    # Standard RFC-compliant address regex
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, address.strip()))


def parse_recipients(raw) -> Tuple[List[str], List[str]]:
    """
    Parse a recipient field into a validated, de-duplicated address list.

    Accepts a comma-, semicolon-, or newline-separated string, or a list.
    Blank entries are dropped and casing is normalised, so that
    "A@x.com, a@x.com" counts as one recipient rather than two.

    Returns (valid_addresses, invalid_entries).
    """
    if raw is None:
        return [], []

    if isinstance(raw, (list, tuple, set)):
        candidates = [str(item) for item in raw]
    else:
        text = str(raw).replace("\r", "\n")
        for sep in (";", "\n"):
            text = text.replace(sep, ",")
        candidates = text.split(",")

    valid: List[str] = []
    invalid: List[str] = []
    seen = set()

    for candidate in candidates:
        addr = candidate.strip().strip('"').strip("'")
        if not addr:
            continue
        if not validate_email(addr):
            invalid.append(addr)
            continue
        key = addr.lower()
        if key in seen:
            continue
        seen.add(key)
        valid.append(addr)

    return valid, invalid


# Provider-side failure modes worth telling apart, because each has a
# different fix and a live demo should never fail ambiguously. Resend
# requires a domain you own before it will send to arbitrary recipients --
# the shared onboarding@resend.dev sender can only reach the account owner.
# See https://resend.com/docs/dashboard/domains/introduction
_PROVIDER_HINTS = {
    401: ("Resend rejected the API key (401). It is invalid or revoked -- generate a "
          "new one at https://resend.com/api-keys and update RESEND_API_KEY in .env."),
    403: ("Resend refused the request (403). This is usually a sending-domain problem: "
          "verify a domain you own at https://resend.com/domains and set "
          "REPORT_FROM_EMAIL to an address on it. The shared onboarding@resend.dev "
          "sender can only deliver to the account owner's own address."),
    422: ('Resend rejected the request as invalid (422). Check the sender format -- '
          'it must be "Display Name <address@your-verified-domain>".'),
    429: "Resend rate limit hit (429). Too many requests in the last second; wait a moment and retry.",
}


class EmailService:
    """
    Client for dispatching investigation reports.

    Two transports are supported, chosen automatically:

    1. Resend (default) -- used whenever RESEND_API_KEY is set.
    2. SMTP fallback -- used when SMTP_USER and SMTP_PASSWORD are present and
       no Resend key is configured.

    WHY THE FALLBACK EXISTS
    -----------------------
    Resend will only deliver to arbitrary recipients once you have verified a
    sending domain you own. Until then it silently restricts the shared
    onboarding@resend.dev sender to the account owner's own address, returning
    HTTP 403. That is an account-configuration limit, not a bug in this code.

    The SMTP transport sidesteps domain verification entirely, because the
    sending identity is a real, already-authenticated mailbox (e.g. a Gmail
    account using an App Password). That makes it a practical option for
    demos and small-scale internal distribution -- senders are NOT spoofable
    this way, which is exactly why it is legitimate rather than a loophole.
    """

    RESEND_API_URL = "https://api.resend.com/emails"

    def __init__(self, api_key: Optional[str] = None, from_email: Optional[str] = None):
        self._api_key = api_key
        self._from_email = from_email

        if not self._api_key:
            self._api_key = os.environ.get("RESEND_API_KEY")
            if not self._api_key and st is not None:
                try:
                    if hasattr(st, "secrets") and "RESEND_API_KEY" in st.secrets:
                        self._api_key = st.secrets["RESEND_API_KEY"]
                except Exception:
                    pass

        if not self._from_email:
            self._from_email = os.environ.get("REPORT_FROM_EMAIL")
            if not self._from_email and st is not None:
                try:
                    if hasattr(st, "secrets") and "REPORT_FROM_EMAIL" in st.secrets:
                        self._from_email = st.secrets["REPORT_FROM_EMAIL"]
                except Exception:
                    pass

        if not self._from_email:
            self._from_email = "QCTD Reports <noreply@example.com>"

        # SMTP fallback config, read only from the environment so that passing
        # an explicit api_key keeps the existing Resend-only behaviour (and
        # keeps the unit tests hermetic).
        self._smtp_host = os.environ.get("SMTP_HOST", "").strip()
        self._smtp_port = int(os.environ.get("SMTP_PORT", "587") or 587)
        self._smtp_user = os.environ.get("SMTP_USER", "").strip()
        self._smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
        self._smtp_use_tls = os.environ.get("SMTP_USE_TLS", "1").strip() not in ("0", "false", "False")

    @property
    def transport(self) -> str:
        """
        Which transport a send would use: 'resend', 'smtp', or 'none'.

        Resend wins when a key is present, since that is the richer path
        (webhooks, deliverability tooling). SMTP is the fallback for when no
        key is configured but SMTP credentials are.
        """
        if self.is_configured:
            return "resend"
        if self._smtp_user and self._smtp_password and self._smtp_host:
            return "smtp"
        return "none"

    @property
    def is_configured(self) -> bool:
        """True if the Resend API key is configured."""
        return bool(self._api_key and self._api_key.strip())

    def send_report(
        self,
        recipient,
        subject: str,
        html_body: str,
        text_body: str
    ) -> EmailSendResult:
        """
        Sends an investigation report email via the Resend API.

        `recipient` may be a single address, a comma/semicolon-separated
        string of them, or a list. All recipients go in the To: field, so
        they can see each other -- fine for an internal SOC report, worth
        knowing before pasting an external address.
        """
        if not self.is_configured:
            if self.transport == "smtp":
                return self._send_via_smtp(addresses, subject, html_body, text_body)
            return EmailSendResult(
                success=False,
                error_message="Email delivery unavailable: RESEND_API_KEY is not configured and no SMTP credentials were found."
            )

        addresses, invalid = parse_recipients(recipient)

        if invalid:
            joined = ", ".join(invalid)
            return EmailSendResult(
                success=False,
                error_message="Validation error: invalid recipient address(es): " + joined
            )

        if not addresses:
            return EmailSendResult(
                success=False,
                error_message="No valid recipient email address was provided."
            )

        headers = {
            "Authorization": f"Bearer {self._api_key.strip()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "QuantumCyberThreatDetection/1.0",
        }

        payload = {
            "from": self._from_email,
            "to": addresses,
            "subject": subject,
            "html": html_body,
            "text": text_body,
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(self.RESEND_API_URL, data=req_data, headers=headers, method="POST")

            with urllib.request.urlopen(req, timeout=15) as response:
                status_code = response.getcode()
                resp_text = response.read().decode("utf-8")
                resp_json = json.loads(resp_text) if resp_text else {}

                if status_code in (200, 201):
                    msg_id = resp_json.get("id")
                    return EmailSendResult(success=True, message_id=msg_id)
                else:
                    return EmailSendResult(
                        success=False,
                        error_message=f"Resend service returned unexpected HTTP status {status_code}."
                    )

        except urllib.error.HTTPError as e:
            raw_err = e.read().decode("utf-8")
            safe_msg = f"HTTP {e.code}"
            try:
                err_dict = json.loads(raw_err)
                if "message" in err_dict:
                    safe_msg = f"{safe_msg}: {err_dict['message']}"
            except Exception:
                safe_msg = f"{safe_msg}: {e.reason}"

            # Lead with the actionable cause where we recognise one, since a
            # bare "HTTP 401" tells an operator nothing about what to change.
            hint = _PROVIDER_HINTS.get(e.code)
            if hint:
                safe_msg = f"{safe_msg} -- {hint}"

            # Never log or leak keys
            return EmailSendResult(success=False, error_message=f"Email provider error ({safe_msg})")

        except urllib.error.URLError as e:
            return EmailSendResult(
                success=False,
                error_message=f"Network error connecting to email provider: {e.reason}"
            )

        except Exception as e:
            return EmailSendResult(
                success=False,
                error_message=f"Unexpected error during email dispatch: {str(e)}"
            )

    def _send_via_smtp(
        self,
        addresses: List[str],
        subject: str,
        html_body: str,
        text_body: str
    ) -> EmailSendResult:
        """
        Deliver via a standard SMTP relay (e.g. Gmail smtp with an App
        Password). Used when no Resend key is configured, so that reports can
        still reach arbitrary recipients without a verified sending domain.
        """
        message = EmailMessage()
        message["From"] = self._from_email
        message["To"] = ", ".join(addresses)
        message["Subject"] = subject
        message.set_content(text_body or "")
        if html_body:
            message.add_alternative(html_body, subtype="html")

        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=20) as server:
                if self._smtp_use_tls:
                    server.starttls()
                server.login(self._smtp_user, self._smtp_password)
                server.send_message(message)
            # SMTP has no provider message id; report a stable local marker so
            # the UI's dispatch de-duplication still has something to record.
            return EmailSendResult(success=True, message_id="smtp-delivered")
        except smtplib.SMTPAuthenticationError:
            return EmailSendResult(
                success=False,
                error_message=(
                    "SMTP authentication failed. Check SMTP_USER / SMTP_PASSWORD -- "
                    "for Gmail use a 16-character App Password, not the account password."
                ),
            )
        except (smtplib.SMTPException, OSError) as e:
            return EmailSendResult(
                success=False,
                error_message=f"SMTP delivery failed: {type(e).__name__}: {e}",
            )
        except Exception as e:
            return EmailSendResult(
                success=False,
                error_message=f"Unexpected error during SMTP dispatch: {type(e).__name__}: {e}",
            )

    # Convenient alias for send_email
    def send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> EmailSendResult:
        return self.send_report(
            recipient=to_email,
            subject=subject,
            html_body=html_content,
            text_body=text_content
        )


def build_report_email_html(report_dict: Dict[str, Any], style: str = "simple") -> Tuple[str, str]:
    """
    Generates high-fidelity responsive HTML and matching plain-text email bodies.
    All dynamic strings are strictly escaped with html.escape to prevent HTML injection.
    Supports 'simple' and 'technical' formats.
    """
    report_id = str(report_dict.get("report_id", "QCTD-UNKNOWN"))
    timestamp = str(report_dict.get("timestamp_utc", "Unknown Time"))
    posture = str(report_dict.get("risk_posture", "UNKNOWN"))
    sim_mode = str(report_dict.get("simulation_mode", "Manual"))
    is_blind = sim_mode == "Blind test"
    revealed = bool(report_dict.get("ground_truth_revealed", False))

    msg_state = str(report_dict.get("message_state", "1"))
    basis = str(report_dict.get("measurement_basis", "Z"))
    shots = str(report_dict.get("shot_count", "512"))

    verdict = str(report_dict.get("detector_verdict", "NORMAL"))
    dev = float(report_dict.get("statistical_deviation", 0.0))
    thresh = float(report_dict.get("calibrated_threshold", 0.0253))
    score = float(report_dict.get("threat_score", 0.0))
    threat_label = str(report_dict.get("threat_label", "NO_THREAT"))

    err_rate = float(report_dict.get("error_rate", 0.0))
    err_thresh = float(report_dict.get("error_threshold", 0.11))
    sec_state = str(report_dict.get("security_state", "SECURE"))

    plain_summary = str(report_dict.get("plain_summary", ""))
    tech_expl = str(report_dict.get("technical_explanation", ""))
    evidence = report_dict.get("simulation_evidence", [])
    research = report_dict.get("external_research", [])
    recs = report_dict.get("recommended_checks", [])
    limits = report_dict.get("known_limitations", [])
    sources = report_dict.get("source_links", [])

    # Color mapping matching SOC theme
    if posture == "CRITICAL":
        badge_bg = "#ff2d55"
        badge_color = "#ffffff"
    elif posture in ("WEAK", "STRONG + ALERT"):
        badge_bg = "#ffc400"
        badge_color = "#10141b"
    else:  # VERY STRONG
        badge_bg = "#00ff88"
        badge_color = "#04110a"

    # HTML Escapes
    e_report_id = html.escape(report_id)
    e_timestamp = html.escape(timestamp)
    e_posture = html.escape(posture)
    e_summary = html.escape(plain_summary)
    e_tech = html.escape(tech_expl)

    # 1. Plain Text Alternative
    text_lines = [
        "===========================================================",
        f"QUANTUM CYBER THREAT DETECTION -- Q-INTEL INVESTIGATION REPORT",
        "===========================================================",
        f"Report ID:     {report_id}",
        f"Timestamp:     {timestamp}",
        f"Security Posture: [{posture}]",
        f"Simulation:    {sim_mode} | Basis: {basis} | Shots: {shots}",
        "-----------------------------------------------------------",
        "",
        "SUMMARY:",
        plain_summary,
        "",
    ]

    if style == "technical":
        text_lines.extend([
            "TECHNICAL ANALYSIS:",
            tech_expl,
            "",
            "CORE TELEMETRY:",
            f"- Statistical Deviation: {dev:.4f} (Threshold: {thresh:.4f})",
            f"- Normalized Threat Score: {score:.2f} (Gate: 1.00)",
            f"- Detector Verdict: {verdict}",
            f"- Teleportation Error Rate: {err_rate * 100:.1f}% (Threshold: {err_thresh * 100:.0f}%)",
            f"- Security State: {sec_state}",
            "",
            "EMPIRICAL EVIDENCE:",
        ])
        for ev in evidence:
            text_lines.append(f"  * {ev}")
        text_lines.append("")

    if research:
        text_lines.append("EXTERNAL RESEARCH FINDINGS (TINYFISH):")
        for rf in research:
            text_lines.append(f"  * {rf}")
        text_lines.append("")

    if sources and style == "technical":
        text_lines.append("CITED TECHNICAL SOURCES:")
        for s in sources:
            s_title = s.get("title", "") if isinstance(s, dict) else getattr(s, "title", "")
            s_url = s.get("url", "") if isinstance(s, dict) else getattr(s, "url", "")
            text_lines.append(f"  * {s_title}: {s_url}")
        text_lines.append("")

    text_lines.extend([
        "RECOMMENDED VERIFICATION CHECKS:",
    ])
    for r in recs:
        text_lines.append(f"  [ ] {r}")
    text_lines.append("")

    text_lines.extend([
        "PROTOTYPE LIMITATIONS & DISCLAIMER:",
    ])
    for lim in limits:
        text_lines.append(f"  ! {lim}")
    text_lines.extend([
        "",
        "DISCLAIMER: This report is generated by an educational simulation prototype.",
        "It does NOT represent confirmed real-world cyberattack detection or physical quantum hardware execution.",
        "==========================================================="
    ])
    plain_text = "\n".join(text_lines)

    # 2. Responsive Branded HTML Body
    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "  <title>Q-Intel Investigation Report</title>",
        "  <style>",
        "    body { margin: 0; padding: 0; background-color: #0b0e14; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #c9d1d9; -webkit-font-smoothing: antialiased; }",
        "    .wrapper { width: 100%; max-width: 660px; margin: 0 auto; padding: 24px 16px; box-sizing: border-box; }",
        "    .card { background-color: #12161e; border: 1px solid rgba(0, 255, 136, 0.22); border-radius: 8px; overflow: hidden; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45); }",
        "    .header { background: linear-gradient(135deg, rgba(0, 255, 136, 0.12), rgba(18, 22, 30, 0.95)); padding: 24px; border-bottom: 1px solid rgba(0, 255, 136, 0.2); }",
        "    .kicker { color: #00ff88; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 6px; }",
        "    .title { color: #f0f6fc; font-size: 20px; font-weight: 700; margin: 0 0 12px 0; letter-spacing: 0.5px; }",
        "    .meta { color: #8b949e; font-size: 12px; font-family: 'SFMono-Regular', Consolas, monospace; margin: 0; }",
        "    .badge { display: inline-block; padding: 6px 14px; border-radius: 4px; font-weight: 800; font-size: 13px; letter-spacing: 1px; margin-top: 14px; }",
        "    .body { padding: 24px; }",
        "    .section-title { font-size: 13px; text-transform: uppercase; letter-spacing: 1.5px; color: #7ee787; margin: 20px 0 10px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 6px; }",
        "    p.text { font-size: 14px; line-height: 1.6; color: #d0d7de; margin: 0 0 14px 0; }",
        "    .metric-grid { display: table; width: 100%; table-layout: fixed; margin: 16px 0; }",
        "    .metric-cell { display: table-cell; padding: 12px; background-color: #161b22; border: 1px solid rgba(255, 255, 255, 0.08); text-align: center; }",
        "    .metric-val { font-size: 18px; font-weight: 700; color: #00ff88; font-family: 'SFMono-Regular', Consolas, monospace; }",
        "    .metric-lbl { font-size: 10px; text-transform: uppercase; color: #8b949e; margin-top: 4px; letter-spacing: 0.5px; }",
        "    ul.list { margin: 8px 0 16px 0; padding-left: 20px; }",
        "    ul.list li { font-size: 13px; line-height: 1.55; color: #c9d1d9; margin-bottom: 6px; }",
        "    .source-link { color: #00ff88; text-decoration: none; word-break: break-all; }",
        "    .source-link:hover { text-decoration: underline; }",
        "    .disclaimer { background-color: rgba(255, 196, 0, 0.06); border-left: 3px solid #ffc400; padding: 12px 16px; margin: 24px 0 0 0; }",
        "    .disclaimer p { margin: 0; font-size: 11px; line-height: 1.5; color: #ffe9a8; }",
        "    .footer { text-align: center; padding: 16px; color: #6e7681; font-size: 11px; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <div class='wrapper'>",
        "    <div class='card'>",
        "      <div class='header'>",
        "        <div class='kicker'>Quantum Cyber Threat Detection &middot; Q-Intel Agent</div>",
        f"        <h1 class='title'>{'Technical Investigation Report' if style == 'technical' else 'Session Investigation Summary'}</h1>",
        f"        <div class='meta'>REPORT ID: {e_report_id} &middot; {e_timestamp}</div>",
        f"        <span class='badge' style='background-color: {badge_bg}; color: {badge_color};'>RISK POSTURE: {e_posture}</span>",
        "      </div>",
        "      <div class='body'>",
        "        <div class='section-title'>Executive Summary</div>",
        f"        <p class='text'>{e_summary}</p>",
    ]

    if style == "technical":
        html_parts.extend([
            "        <div class='section-title'>Technical Protocol Telemetry</div>",
            f"        <p class='text'>{e_tech}</p>",
            "        <div class='metric-grid'>",
            f"          <div class='metric-cell'><div class='metric-val'>{err_rate * 100:.1f}%</div><div class='metric-lbl'>Error Rate ({sec_state})</div></div>",
            f"          <div class='metric-cell'><div class='metric-val'>{dev:.4f}</div><div class='metric-lbl'>Statistical Dev</div></div>",
            f"          <div class='metric-cell'><div class='metric-val'>{score:.2f}</div><div class='metric-lbl'>Threat Score</div></div>",
            "        </div>",
            "        <div class='section-title'>Empirical Evidence</div>",
            "        <ul class='list'>",
        ])
        for ev in evidence:
            html_parts.append(f"          <li>{html.escape(ev)}</li>")
        html_parts.append("        </ul>")

    if research:
        html_parts.extend([
            "        <div class='section-title'>External Technical Research (TinyFish)</div>",
            "        <ul class='list'>",
        ])
        for rf in research:
            html_parts.append(f"          <li>{html.escape(rf)}</li>")
        html_parts.append("        </ul>")

    if sources and style == "technical":
        html_parts.extend([
            "        <div class='section-title'>Cited Technical Sources</div>",
            "        <ul class='list'>",
        ])
        for s in sources:
            s_title = s.get("title", "") if isinstance(s, dict) else getattr(s, "title", "")
            s_url = s.get("url", "") if isinstance(s, dict) else getattr(s, "url", "")
            es_title = html.escape(s_title or "Reference Document")
            es_url = html.escape(s_url or "#")
            html_parts.append(f"          <li><a class='source-link' href='{es_url}' target='_blank' rel='noopener noreferrer'>{es_title}</a></li>")
        html_parts.append("        </ul>")

    html_parts.extend([
        "        <div class='section-title'>Recommended Verification Actions</div>",
        "        <ul class='list'>",
    ])
    for r in recs:
        html_parts.append(f"          <li>{html.escape(r)}</li>")
    html_parts.append("        </ul>")

    html_parts.extend([
        "        <div class='disclaimer'>",
        "          <p><strong>Prototype / Educational Notice:</strong> This analysis was performed on an educational Qiskit Aer simulation model. It does not certify production quantum security guarantees or reflect real-world adversarial attribution.</p>",
        "        </div>",
        "      </div>",
        "    </div>",
        "    <div class='footer'>Quantum Cyber Threat Detection &middot; Team: Vinayak Dev Tiwari, Shivansh Tiwari, Ballabh Utkarsh Singh</div>",
        "  </div>",
        "</body>",
        "</html>"
    ])

    html_body = "\n".join(html_parts)
    return html_body, plain_text
