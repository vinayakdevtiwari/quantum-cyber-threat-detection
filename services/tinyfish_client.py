"""
services/tinyfish_client.py

Robust client for the official TinyFish API:
- Search API (GET https://api.search.tinyfish.ai)
- Fetch API (POST https://api.fetch.tinyfish.ai)
- Agent API (POST /v1/research/async, GET /v1/research-run/{id})

Features:
- Structured data classes and validated models
- Exponential backoff retry for transient 429 and 5xx errors
- Strict non-retry on client errors (401, 403, 400)
- Bounded timeouts and safe untrusted content sanitization
- Never logs or leaks API credentials
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Load .env if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Safe Streamlit secret access if available
try:
    import streamlit as st
except ImportError:
    st = None


class TinyFishError(Exception):
    """Base exception for TinyFish client errors."""
    pass


class TinyFishAuthError(TinyFishError):
    """Exception raised for authentication errors (401/403)."""
    pass


class TinyFishRateLimitError(TinyFishError):
    """Exception raised for rate limit errors (429)."""
    pass


class TinyFishTimeoutError(TinyFishError):
    """Exception raised for timeout errors."""
    pass


class TinyFishNotConfiguredError(TinyFishError):
    """Exception raised when the TinyFish client is missing an API key."""
    pass


@dataclass
class SearchResultItem:
    title: str
    url: str
    snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return {"title": self.title, "url": self.url, "snippet": self.snippet}


@dataclass
class SearchResult:
    items: List[SearchResultItem]
    query: str
    status: str = "success"

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)


@dataclass
class FetchResultItem:
    url: str
    title: str
    content: str
    status: str


@dataclass
class FetchResult:
    items: List[FetchResultItem]
    errors: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ResearchSource:
    title: str
    url: str


@dataclass
class ResearchResult:
    run_id: str
    status: str  # "completed", "running", "failed", "timeout", "not_configured"
    report: Optional[str] = None
    sources: List[ResearchSource] = field(default_factory=list)
    error: Optional[str] = None


class TinyFishClient:
    """Client for TinyFish Search, Fetch, and Deep Research APIs."""

    SEARCH_ENDPOINT = os.environ.get("TINYFISH_SEARCH_URL", "https://api.search.tinyfish.ai")
    FETCH_ENDPOINT = os.environ.get("TINYFISH_FETCH_URL", "https://api.fetch.tinyfish.ai")
    AGENT_BASE_URL = os.environ.get("TINYFISH_AGENT_URL", "https://agent.tinyfish.ai/v1")

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key
        if not self._api_key:
            self._api_key = os.environ.get("TINYFISH_API_KEY")
            if not self._api_key and st is not None:
                try:
                    if hasattr(st, "secrets") and "TINYFISH_API_KEY" in st.secrets:
                        self._api_key = st.secrets["TINYFISH_API_KEY"]
                except Exception:
                    pass

    @property
    def is_configured(self) -> bool:
        """Return True if an API key is present and non-empty."""
        return bool(self._api_key and self._api_key.strip())

    def _get_headers(self) -> Dict[str, str]:
        if not self.is_configured:
            raise TinyFishNotConfiguredError("TinyFish API key is not configured. Set TINYFISH_API_KEY environment variable.")
        return {
            "X-API-Key": self._api_key.strip(),
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "QuantumCyberThreatDetection/1.0",
        }

    def _execute_http(
        self,
        url: str,
        method: str = "GET",
        data: Optional[bytes] = None,
        timeout: int = 30,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """Executes HTTP request with bounded retry and strict error discrimination."""
        req = urllib.request.Request(url, data=data, headers=self._get_headers(), method=method)
        base_delay = 1.0

        for attempt in range(max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    raw_data = response.read().decode("utf-8")
                    if not raw_data.strip():
                        return {}
                    try:
                        return json.loads(raw_data)
                    except json.JSONDecodeError as jde:
                        raise TinyFishError(f"Malformed JSON response from TinyFish API: {str(jde)}")

            except urllib.error.HTTPError as e:
                # Do NOT retry 401/403 or 400
                if e.code in (401, 403):
                    raise TinyFishAuthError(f"TinyFish authentication error ({e.code}): Check TINYFISH_API_KEY.")
                elif e.code == 429:
                    if attempt < max_retries:
                        time.sleep(base_delay * (2 ** attempt))
                        continue
                    raise TinyFishRateLimitError(f"TinyFish rate limit reached (HTTP 429).")
                elif 500 <= e.code < 600:
                    if attempt < max_retries:
                        time.sleep(base_delay * (2 ** attempt))
                        continue
                    raise TinyFishError(f"TinyFish server error ({e.code}).")
                else:
                    raise TinyFishError(f"TinyFish HTTP error ({e.code}): {e.reason}")

            except urllib.error.URLError as e:
                if isinstance(e.reason, TimeoutError) or "timed out" in str(e.reason).lower():
                    if attempt < max_retries:
                        time.sleep(base_delay * (2 ** attempt))
                        continue
                    raise TinyFishTimeoutError(f"TinyFish request timed out after {timeout} seconds.")
                raise TinyFishError(f"TinyFish connection error: {e.reason}")

            except TimeoutError:
                if attempt < max_retries:
                    time.sleep(base_delay * (2 ** attempt))
                    continue
                raise TinyFishTimeoutError(f"TinyFish request timed out after {timeout} seconds.")

        raise TinyFishError("TinyFish max retries exceeded.")

    def search(self, query: str, num_results: int = 5) -> SearchResult:
        """
        Search technical literature and quantum documentation.
        Endpoint: GET https://api.search.tinyfish.ai (or /v1/search)
        """
        if not self.is_configured:
            raise TinyFishNotConfiguredError("TinyFish API key is not configured.")

        # Bound number of results to prevent excessive token or bandwidth usage
        bounded_num = max(1, min(int(num_results), 10))
        params = {"query": query, "num_results": bounded_num}
        query_string = urllib.parse.urlencode(params)
        url = f"{self.SEARCH_ENDPOINT}?{query_string}"

        response = self._execute_http(url, method="GET", timeout=25)

        items: List[SearchResultItem] = []
        raw_results = response.get("results")
        if raw_results and isinstance(raw_results, list):
            for res in raw_results:
                if isinstance(res, dict):
                    # Sanitize snippet and title length
                    title = str(res.get("title", "Untitled Source"))[:250]
                    res_url = str(res.get("url", ""))[:500]
                    snippet = str(res.get("snippet", ""))[:600]
                    items.append(SearchResultItem(title=title, url=res_url, snippet=snippet))

        return SearchResult(items=items, query=query, status="success")

    def fetch_urls(self, urls: List[str], format: str = "markdown") -> FetchResult:
        """
        Fetch up to 5 URLs via TinyFish Fetch API.
        Endpoint: POST https://api.fetch.tinyfish.ai
        """
        if not self.is_configured:
            raise TinyFishNotConfiguredError("TinyFish API key is not configured.")

        if not urls:
            return FetchResult(items=[], errors=[])

        # Bounded URL list to protect quota
        clean_urls = [u.strip() for u in urls if u and isinstance(u, str)][:5]
        body = {"urls": clean_urls, "format": format}
        data = json.dumps(body).encode("utf-8")

        response = self._execute_http(self.FETCH_ENDPOINT, method="POST", data=data, timeout=35)

        items: List[FetchResultItem] = []
        raw_items = response.get("results")
        if raw_items and isinstance(raw_items, list):
            for it in raw_items:
                if isinstance(it, dict):
                    # Strip/bound content
                    content = str(it.get("content", ""))[:4000]
                    items.append(FetchResultItem(
                        url=str(it.get("url", "")),
                        title=str(it.get("title", "Fetched Article"))[:250],
                        content=content,
                        status=str(it.get("status", "ok"))
                    ))

        errors = response.get("errors", [])
        return FetchResult(items=items, errors=errors if isinstance(errors, list) else [])

    def start_deep_research(self, query: str, max_iterations: int = 3) -> str:
        """
        Enqueues a deep research task via Agent API. Returns run_id.
        Endpoint: POST https://agent.tinyfish.ai/v1/research/async
        """
        if not self.is_configured:
            raise TinyFishNotConfiguredError("TinyFish API key is not configured.")

        url = f"{self.AGENT_BASE_URL}/research/async"
        body = {
            "query": query,
            "max_iterations": max(1, min(max_iterations, 5)),
            "output_schema": {
                "type": "object",
                "properties": {
                    "findings": {"type": "array", "items": {"type": "string"}},
                    "analysis": {"type": "string"},
                    "sources": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": {"type": "string"},
                                "url": {"type": "string"}
                            }
                        }
                    }
                }
            }
        }
        data = json.dumps(body).encode("utf-8")

        response = self._execute_http(url, method="POST", data=data, timeout=30)
        run_id = response.get("id") or response.get("run_id")
        if not run_id:
            raise TinyFishError("TinyFish Agent API response did not contain a valid run ID.")
        return str(run_id)

    def get_research_status(self, run_id: str) -> ResearchResult:
        """
        Polls run status for deep research task.
        Endpoint: GET https://agent.tinyfish.ai/v1/research-run/{id}
        """
        if not self.is_configured:
            raise TinyFishNotConfiguredError("TinyFish API key is not configured.")

        url = f"{self.AGENT_BASE_URL}/research-run/{run_id}"
        response = self._execute_http(url, method="GET", timeout=25)

        status = response.get("status", "unknown")
        result_payload = response.get("result") or {}

        sources: List[ResearchSource] = []
        raw_sources = result_payload.get("sources") or response.get("sources") or []
        if isinstance(raw_sources, list):
            for s in raw_sources:
                if isinstance(s, dict):
                    sources.append(ResearchSource(
                        title=str(s.get("title", "Research Reference")),
                        url=str(s.get("url", ""))
                    ))

        report_text = result_payload.get("report") or result_payload.get("analysis")
        if not report_text and "findings" in result_payload and isinstance(result_payload["findings"], list):
            report_text = "\n".join(f"- {f}" for f in result_payload["findings"])

        err_msg = response.get("error") or result_payload.get("error")

        return ResearchResult(
            run_id=run_id,
            status=status,
            report=report_text,
            sources=sources,
            error=str(err_msg) if err_msg else None
        )

    def run_deep_research(self, query: str, max_iterations: int = 3, timeout: int = 90) -> ResearchResult:
        """
        Synchronously initiates and polls deep research workflow until completion or timeout.
        """
        run_id = self.start_deep_research(query, max_iterations=max_iterations)
        start_time = time.time()

        while True:
            if time.time() - start_time > timeout:
                return ResearchResult(
                    run_id=run_id,
                    status="timeout",
                    error=f"Research task timed out after {timeout} seconds."
                )

            res = self.get_research_status(run_id)
            if res.status in ("completed", "failed", "error", "succeeded"):
                return res

            time.sleep(3.0)

    # Friendly alias
    deep_research = run_deep_research
