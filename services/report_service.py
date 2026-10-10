"""
services/report_service.py

Orchestrates the Q-Intel AI Investigation workflow.
Connects simulation telemetry, TinyFish technical research retrieval,
structured report synthesis, and transactional email distribution.
"""

from typing import Dict, Any, Tuple, List, Optional
import html

from models.investigation_report import InvestigationReport, SourceLink
from services.tinyfish_client import (
    TinyFishClient,
    TinyFishError,
    TinyFishAuthError,
    TinyFishRateLimitError,
    TinyFishTimeoutError,
    TinyFishNotConfiguredError,
    SearchResult,
    FetchResult,
    ResearchResult,
)
from services.email_service import (
    EmailService,
    build_report_email_html,
    validate_email,
    parse_recipients,
    EmailSendResult,
)


class QIntelAgent:
    """
    Q-Intel AI investigation agent.
    Coordinates evidence-aware investigation across simulation outputs and TinyFish research.
    """

    def __init__(
        self,
        tinyfish_client: Optional[TinyFishClient] = None,
        email_service: Optional[EmailService] = None,
    ):
        self.tinyfish = tinyfish_client if tinyfish_client is not None else TinyFishClient()
        self.email_service = email_service if email_service is not None else EmailService()

    @property
    def research_available(self) -> bool:
        """True if TinyFish API key is configured."""
        return self.tinyfish.is_configured

    @property
    def email_available(self) -> bool:
        """True if either the Resend key or the SMTP fallback is configured."""
        return self.email_service.transport != "none"

    def _build_research_query(self, session_data: Dict[str, Any]) -> str:
        """
        Builds a focused, technical query based on the empirical session results.
        Never incorporates user email or private information.
        """
        # Determine signals
        threat_label = session_data.get("threat_label", "")
        sec_state = session_data.get("sec_state", session_data.get("security_state", ""))
        basis = session_data.get("session_basis", session_data.get("measurement_basis", "Z"))
        dev = float(session_data.get("deviation", session_data.get("statistical_deviation", 0.0)))

        if threat_label == "THREAT" and sec_state == "INSECURE":
            return f"quantum digital signature eavesdropping detection chi-squared deviation {basis} basis teleportation error rate"
        elif threat_label == "THREAT":
            return f"quantum digital signature statistical distribution anomaly detection Pauli error {basis} basis"
        elif sec_state == "INSECURE":
            return f"quantum teleportation bit error rate depolarizing channel noise threshold decoy state"
        else:
            return f"quantum digital signature teleportation protocol honest verification chi-squared benchmark"

    def investigate_session(
        self,
        session_data: Dict[str, Any],
        calibrated_threshold: float = 0.0253
    ) -> InvestigationReport:
        """
        Interprets session telemetry, gathers external technical evidence if TinyFish is configured,
        and compiles a structured, evidence-aware InvestigationReport.
        """
        if not session_data:
            raise ValueError("session_data cannot be empty when conducting an investigation.")

        # 1. Instantiate the foundational report from verified simulation outputs
        report = InvestigationReport.create_from_session(session_data, calibrated_threshold=calibrated_threshold)

        # 2. Check if TinyFish research tools are configured
        if not self.research_available:
            report.research_status = "not_configured"
            report.known_limitations.append(
                "Report generated without live external research (TinyFish API not configured on server)."
            )
            return report

        # 3. Retrieve external research via TinyFish Search and Fetch
        query = self._build_research_query(session_data)
        external_findings: List[str] = []
        source_links: List[SourceLink] = []

        try:
            search_result = self.tinyfish.search(query=query, num_results=4)

            if not search_result.items:
                report.research_status = "unavailable"
                external_findings.append(f"No specific external literature matches returned for query: '{query}'.")
            else:
                top_urls = []
                for item in search_result.items:
                    link = SourceLink(title=item.title, url=item.url, snippet=item.snippet)
                    source_links.append(link)
                    if item.url and item.url.startswith("http"):
                        top_urls.append(item.url)

                    # Extract concise findings from snippets
                    if item.snippet:
                        clean_snippet = item.snippet.replace("\n", " ").strip()
                        if len(clean_snippet) > 280:
                            clean_snippet = clean_snippet[:277] + "..."
                        external_findings.append(f"{item.title}: {clean_snippet}")

                # Fetch clean content from top 2 URLs for deeper evidence extraction
                if top_urls:
                    try:
                        fetch_res = self.tinyfish.fetch_urls(top_urls[:2], format="markdown")
                        for f_item in fetch_res.items:
                            if f_item.content and len(f_item.content) > 100:
                                # Extract clean 1-2 sentence evidence summary
                                lines = [line.strip() for line in f_item.content.split("\n") if len(line.strip()) > 40]
                                if lines:
                                    snippet = lines[0][:260] + "..." if len(lines[0]) > 260 else lines[0]
                                    external_findings.append(f"Evidence from {f_item.title}: \"{snippet}\"")
                    except Exception:
                        # Non-fatal if fetch encounters page blocks; search snippets still provide value
                        pass

                report.research_status = "completed"

        except TinyFishAuthError:
            report.research_status = "error"
            report.known_limitations.append("TinyFish live research unavailable: Authentication failed. Verify TINYFISH_API_KEY.")
        except TinyFishRateLimitError:
            report.research_status = "unavailable"
            report.known_limitations.append("TinyFish live research temporarily unavailable due to rate limits.")
        except TinyFishTimeoutError:
            report.research_status = "unavailable"
            report.known_limitations.append("TinyFish live research timed out connecting to remote API.")
        except TinyFishError as te:
            report.research_status = "error"
            report.known_limitations.append(f"TinyFish live research error: {str(te)}")
        except Exception as e:
            report.research_status = "error"
            report.known_limitations.append(f"Unexpected research engine exception: {str(e)}")

        # 4. Integrate research findings into report
        report.update_research(
            external_findings=external_findings,
            sources=source_links,
            status=report.research_status
        )

        return report

    def run_deep_research(self, report: InvestigationReport, question: str) -> InvestigationReport:
        """
        Executes an intentional, deep research task using the TinyFish Agent API.
        Clearly delineated action that investigates an explicitly posed technical question.
        """
        if not self.research_available:
            report.research_status = "not_configured"
            report.known_limitations.append("Deep research unavailable (TINYFISH_API_KEY not configured).")
            return report

        clean_question = question.strip() if question else (
            f"What are established statistical deviation and error rate thresholds for detecting "
            f"quantum channel manipulation in teleportation-based QDS protocols?"
        )

        try:
            res: ResearchResult = self.tinyfish.run_deep_research(query=clean_question, max_iterations=2, timeout=60)

            if res.status in ("completed", "succeeded") and res.report:
                report.external_research.append(f"Deep Research Synthesis: {res.report}")
                for src in res.sources:
                    report.source_links.append(SourceLink(title=src.title, url=src.url))
                report.research_status = "completed"
            elif res.status == "timeout":
                report.research_status = "unavailable"
                report.known_limitations.append("Deep research task timed out before completing iterations.")
            else:
                report.research_status = "error"
                report.known_limitations.append(f"Deep research task ended with status '{res.status}': {res.error or 'No details'}")

        except Exception as e:
            report.research_status = "error"
            report.known_limitations.append(f"Deep research task failed: {str(e)}")

        return report

    def generate_report_content(self, report: InvestigationReport, style: str = "simple") -> Tuple[str, str]:
        """
        Produces (html_body, plain_text_body) for preview and email distribution.
        """
        return build_report_email_html(report.to_dict(), style=style)

    def send_email_report(
        self,
        report: InvestigationReport,
        recipient: str,
        style: str = "simple"
    ) -> EmailSendResult:
        """
        Validates the report and recipient, formats the email in chosen style,
        and dispatches it using EmailService.
        """
        if not report:
            return EmailSendResult(success=False, error_message="Cannot send an empty or ungenerated report.")

        validation_errors = report.validate()
        if validation_errors:
            return EmailSendResult(
                success=False,
                error_message=f"Report validation failed: {'; '.join(validation_errors)}"
            )

        addresses, invalid = parse_recipients(recipient)

        if invalid:
            return EmailSendResult(
                success=False,
                error_message='Invalid recipient email address: ' + ', '.join(invalid)
            )

        if not addresses:
            return EmailSendResult(
                success=False,
                error_message='No valid recipient email address was provided.'
            )

        if not self.email_available:
            return EmailSendResult(
                success=False,
                error_message="Email delivery unavailable: RESEND_API_KEY is not configured and no SMTP credentials were found."
            )

        html_body, text_body = self.generate_report_content(report, style=style)
        subject = f"QCTD Investigation Report [{report.risk_posture}] - {report.report_id[:8]}"

        return self.email_service.send_report(
            recipient=addresses,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )
