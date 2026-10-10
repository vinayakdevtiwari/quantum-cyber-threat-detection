"""
tests/test_tinyfish_client.py

Automated tests for TinyFish API client:
- Successful Search response parsing
- Successful Fetch response parsing
- Agent API success & structured output parsing
- Auth errors (401/403)
- Rate-limit errors (429)
- Timeout errors
- Malformed response errors
- Missing API key behavior
- Empty or irrelevant research results
"""

import json
import io
import urllib.error
from unittest.mock import patch, MagicMock
import pytest

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


def _mock_response(status_code: int, data: dict):
    """Helper to mock urllib.request.urlopen response."""
    raw = json.dumps(data).encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = raw
    resp.getcode.return_value = status_code
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = None
    return resp


def test_missing_api_key_raises_error():
    """Verify missing API key raises TinyFishNotConfiguredError."""
    with patch.dict("os.environ", {}, clear=True):
        client = TinyFishClient(api_key=None)
        assert client.is_configured is False
        with pytest.raises(TinyFishNotConfiguredError):
            client.search("quantum teleportation")
        with pytest.raises(TinyFishNotConfiguredError):
            client.fetch_urls(["https://example.com"])
        with pytest.raises(TinyFishNotConfiguredError):
            client.start_deep_research("quantum attack")


def test_search_successful_parsing():
    """Verify successful Search response parsing."""
    client = TinyFishClient(api_key="test_tf_key")
    fake_data = {
        "results": [
            {
                "title": "Quantum Digital Signatures Protocol",
                "url": "https://arxiv.org/abs/1234.5678",
                "snippet": "Analysis of multi-party QDS protocols using decoy states.",
            },
            {
                "title": "Quantum Teleportation Error Mitigation",
                "url": "https://nature.com/articles/qtelp",
                "snippet": "Depolarizing noise models in teleportation.",
            },
        ]
    }

    with patch("urllib.request.urlopen", return_value=_mock_response(200, fake_data)):
        res = client.search("QDS teleportation error rate", num_results=2)
        assert isinstance(res, SearchResult)
        assert len(res.items) == 2
        assert res.items[0].title == "Quantum Digital Signatures Protocol"
        assert res.items[0].url == "https://arxiv.org/abs/1234.5678"
        assert "decoy states" in res.items[0].snippet


def test_search_empty_results():
    """Verify empty search results are parsed safely."""
    client = TinyFishClient(api_key="test_tf_key")
    fake_data = {"results": []}

    with patch("urllib.request.urlopen", return_value=_mock_response(200, fake_data)):
        res = client.search("obscure quantum term query", num_results=5)
        assert isinstance(res, SearchResult)
        assert len(res.items) == 0


def test_fetch_successful_parsing():
    """Verify successful Fetch response parsing."""
    client = TinyFishClient(api_key="test_tf_key")
    fake_data = {
        "results": [
            {
                "url": "https://arxiv.org/abs/1234.5678",
                "title": "Quantum Digital Signatures",
                "content": "# QDS Overview\nQuantum digital signatures provide non-repudiation.",
                "status": "ok",
            }
        ],
        "errors": [],
    }

    with patch("urllib.request.urlopen", return_value=_mock_response(200, fake_data)):
        res = client.fetch_urls(["https://arxiv.org/abs/1234.5678"], format="markdown")
        assert isinstance(res, FetchResult)
        assert len(res.items) == 1
        assert res.items[0].title == "Quantum Digital Signatures"
        assert "non-repudiation" in res.items[0].content


def test_agent_api_deep_research_success():
    """Verify Agent API start and status polling with structured output."""
    client = TinyFishClient(api_key="test_tf_key")

    start_data = {"id": "run_test_987"}
    status_data = {
        "status": "completed",
        "result": {
            "report": "Chi-squared deviations above 0.02 indicate significant channel disturbance.",
            "sources": [
                {"title": "Physical Review A Paper", "url": "https://pra.aps.org/123"}
            ],
        },
    }

    with patch("urllib.request.urlopen") as mock_url:
        mock_url.side_effect = [
            _mock_response(200, start_data),
            _mock_response(200, status_data),
        ]
        res = client.run_deep_research("quantum noise bounds", max_iterations=1, timeout=10)
        assert isinstance(res, ResearchResult)
        assert res.status == "completed"
        assert res.run_id == "run_test_987"
        assert "Chi-squared deviations" in res.report
        assert len(res.sources) == 1
        assert res.sources[0].title == "Physical Review A Paper"


def test_auth_error_handling():
    """Verify HTTP 401 raises TinyFishAuthError without retrying."""
    client = TinyFishClient(api_key="invalid_key")
    http_error = urllib.error.HTTPError(
        url="https://api.search.tinyfish.ai",
        code=401,
        msg="Unauthorized",
        hdrs={},
        fp=io.BytesIO(b'{"message": "Invalid API key"}')
    )

    with patch("urllib.request.urlopen", side_effect=http_error) as mock_url:
        with pytest.raises(TinyFishAuthError):
            client.search("test")
        # Ensure it didn't retry 401
        assert mock_url.call_count == 1


def test_rate_limit_error_handling():
    """Verify HTTP 429 raises TinyFishRateLimitError after retries."""
    client = TinyFishClient(api_key="test_key")
    http_error = urllib.error.HTTPError(
        url="https://api.search.tinyfish.ai",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=io.BytesIO(b'{"message": "Rate limit exceeded"}')
    )

    with patch("time.sleep", return_value=None):
        with patch("urllib.request.urlopen", side_effect=http_error) as mock_url:
            with pytest.raises(TinyFishRateLimitError):
                client.search("test")
            # Max 2 retries -> 3 attempts total
            assert mock_url.call_count == 3


def test_timeout_error_handling():
    """Verify request timeout raises TinyFishTimeoutError."""
    client = TinyFishClient(api_key="test_key")
    url_error = urllib.error.URLError(reason=TimeoutError("The read operation timed out"))

    with patch("time.sleep", return_value=None):
        with patch("urllib.request.urlopen", side_effect=url_error):
            with pytest.raises(TinyFishTimeoutError):
                client.search("test")


def test_malformed_json_response_handling():
    """Verify non-JSON response raises TinyFishError cleanly."""
    client = TinyFishClient(api_key="test_key")
    resp = MagicMock()
    resp.read.return_value = b"<html><head><title>502 Bad Gateway</title></head><body>Bad Gateway</body></html>"
    resp.getcode.return_value = 200
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = None

    with patch("urllib.request.urlopen", return_value=resp):
        with pytest.raises(TinyFishError) as exc_info:
            client.search("test")
        assert "Malformed JSON" in str(exc_info.value)
