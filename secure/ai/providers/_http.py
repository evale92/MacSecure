"""
secure/ai/providers/_http.py — the one seam every local-model provider
goes through, mirroring secure/threatintel/providers/_http.py's own
"isolate the one real I/O call behind a tiny seam module" convention
(itself mirroring secure/integrations/*/_shell.py for subprocess
calls). Stdlib `urllib.request` only — no third-party HTTP client.

Adds a POST-with-JSON-body helper alongside the GET-JSON helper, since
every local LLM server's chat/completions endpoint is a POST — neither
threatintel's nor any other existing _http.py in this codebase needed
that shape before now.
"""

from __future__ import annotations

import json as json_module
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


@dataclass
class HttpResult:
    ok: bool
    status_code: "Optional[int]"
    json: "Optional[dict]"
    text: str
    error: "Optional[str]"


def _do_request(request: "urllib.request.Request", timeout: float) -> HttpResult:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status_code = response.status
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        parsed = None
        try:
            parsed = json_module.loads(body) if body else None
        except (ValueError, TypeError):
            parsed = None
        return HttpResult(ok=False, status_code=exc.code, json=parsed, text=body, error=f"HTTP {exc.code}")
    except urllib.error.URLError as exc:
        return HttpResult(ok=False, status_code=None, json=None, text="", error=str(exc.reason))
    except (TimeoutError, OSError) as exc:
        return HttpResult(ok=False, status_code=None, json=None, text="", error=str(exc))

    try:
        parsed = json_module.loads(body) if body else None
    except (ValueError, TypeError) as exc:
        return HttpResult(
            ok=True, status_code=status_code, json=None, text=body,
            error=f"response was not valid JSON: {exc}",
        )
    return HttpResult(ok=True, status_code=status_code, json=parsed, text=body, error=None)


def http_get_json(url: str, headers: "Optional[dict]" = None, timeout: float = 10.0) -> HttpResult:
    """A single GET request, parsed as JSON on success. Never raises."""
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    return _do_request(request, timeout)


def http_post_json(
    url: str, body: dict, headers: "Optional[dict]" = None, timeout: float = 60.0
) -> HttpResult:
    """A single POST request with a JSON body, parsed as JSON on
    success. Never raises — every failure mode (network error, timeout,
    non-2xx status, unparseable body) comes back as a populated
    HttpResult, so a provider's own complete() can turn any of them
    into an honest ProviderCompletionResult without a try/except of its
    own.
    """
    encoded = json_module.dumps(body).encode("utf-8")
    merged_headers = {"Content-Type": "application/json"}
    merged_headers.update(headers or {})
    request = urllib.request.Request(url, data=encoded, headers=merged_headers, method="POST")
    return _do_request(request, timeout)
