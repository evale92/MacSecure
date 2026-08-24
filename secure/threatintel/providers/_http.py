"""
secure/threatintel/providers/_http.py — the one seam every network-
capable threat-intelligence provider goes through, so its actual
outbound call is a single, easily-mocked function (the same "isolate
the one real I/O call behind a tiny seam module" convention
secure/integrations/*/​_shell.py already uses for subprocess calls).

Stdlib `urllib.request` only — no third-party HTTP client, matching
this project's existing "no new dependency unless there is genuinely
no standard-library way" discipline (see requirements.txt's own
comments). A provider module never imports `urllib` directly; it always
goes through `http_get_json()` here, so tests can monkeypatch exactly
one function to simulate any provider response without a real network
call.
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


def http_get_json(
    url: str, headers: "Optional[dict]" = None, timeout: float = 10.0
) -> HttpResult:
    """A single GET request, parsed as JSON on success. Never raises —
    every failure mode (network error, timeout, non-2xx status,
    unparseable body) comes back as a populated HttpResult instead, so
    a provider's own lookup() can turn any of them into an honest
    ProviderLookupResult without a try/except of its own.
    """
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
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
        return HttpResult(
            ok=False, status_code=exc.code, json=parsed, text=body, error=f"HTTP {exc.code}",
        )
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
