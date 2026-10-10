"""
services package for Quantum Cyber Threat Detection.
Provides TinyFish client, Email delivery service, and Q-Intel investigation agent.
"""

from .tinyfish_client import TinyFishClient, TinyFishError
from .email_service import EmailService, EmailSendResult, validate_email, build_report_email_html
from .report_service import QIntelAgent

__all__ = [
    "TinyFishClient",
    "TinyFishError",
    "EmailService",
    "EmailSendResult",
    "validate_email",
    "build_report_email_html",
    "QIntelAgent",
]
