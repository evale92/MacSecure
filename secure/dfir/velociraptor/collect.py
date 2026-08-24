"""
secure/dfir/velociraptor/collect.py — runs exactly ONE Velociraptor
artifact collection and returns its outcome. This is the one function
in this whole package that actually starts a subprocess to collect
forensic data — never called by a scan, by run-all, or by anything
else that isn't the explicit, user-approved
`secure dfir collect` command (see secure/dfir/collector.py, the only
caller).

Best-effort CLI invocation, not empirically validated (see this
package's own __init__.py docstring): Velociraptor's documented
offline/local collector usage is
`velociraptor artifacts collect <Artifact.Name> [--args Key=Value ...]
--format jsonl`, run against Velociraptor's own bundled default
artifact definitions (no server, no separate artifact-pack config
needed for a built-in artifact name) — that is the invocation built
here. If a real install's actual flags differ, only `_build_args()`
below needs to change; nothing about CollectionOutcome, the
allowlist check, or storage is affected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from secure.config import AppConfig
from secure.dfir.velociraptor._shell import run, try_get_version
from secure.dfir.velociraptor.parser import parse_jsonl
from secure.integrations.base import STATUS_DEGRADED, STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE

DEFAULT_COLLECTION_TIMEOUT_SECONDS = 120.0


@dataclass(frozen=True)
class CollectionOutcome:
    """The result of one collection attempt. `status` is always one of
    secure/integrations/base.py's own STATUS_* constants — see this
    package's own __init__.py rule 2 and rule 3: UNAVAILABLE/ERROR here
    must never be read downstream as "ran, found nothing." `rows` is
    always `[]` for a non-OK/DEGRADED status — there is never partial
    data attached to a failed collection that a caller might mistake
    for a real (if empty) result.
    """

    status: str
    detail: str
    tool_version: "Optional[str]"
    started_at: "Optional[str]"
    completed_at: "Optional[str]"
    rows: List[dict] = field(default_factory=list)
    malformed_row_count: int = 0


def _build_args(artifact_name: str, parameters: Dict[str, str]) -> List[str]:
    args = ["artifacts", "collect", artifact_name, "--format", "jsonl"]
    for key, value in parameters.items():
        args.extend(["--args", f"{key}={value}"])
    return args


def run_collection(
    cfg: AppConfig,
    artifact_name: str,
    parameters: "Dict[str, str] | None" = None,
    *,
    timeout: float = DEFAULT_COLLECTION_TIMEOUT_SECONDS,
) -> CollectionOutcome:
    """Run `artifact_name` (already allowlist-checked by the caller —
    see collector.py) with `parameters`, and return its outcome.
    Never raises: any subprocess failure (missing binary, timeout,
    nonzero exit) is captured as UNAVAILABLE/ERROR, never an exception
    that could abort a caller mid-way through recording a collection.
    """
    parameters = parameters or {}
    binary = cfg.velociraptor_binary_resolved()
    started_at = datetime.now(timezone.utc).isoformat()

    result = run(binary, _build_args(artifact_name, parameters), timeout=timeout)
    completed_at = datetime.now(timezone.utc).isoformat()

    if result.returncode is None and "not found" in result.stderr:
        return CollectionOutcome(
            status=STATUS_UNAVAILABLE,
            detail=f"velociraptor binary not found ({binary!r}). Set AppConfig."
            "velociraptor_binary_path if it's installed somewhere not on PATH.",
            tool_version=None,
            started_at=None,
            completed_at=None,
        )
    # A second, best-effort `velociraptor version` call — the collection
    # call itself returns JSONL result rows, never a version string, so
    # tool_version provenance needs its own separate (optional, never
    # required) round trip, the same "version discovery is a distinct
    # concern from the real work" split suricata/_shell.py's own
    # try_get_version() already establishes.
    tool_version = try_get_version(binary)

    if result.returncode is None:
        # Timed out — the binary IS present (a missing binary is caught
        # above), so this is an ERROR (something went wrong with this
        # specific attempt), not routine unavailability.
        return CollectionOutcome(
            status=STATUS_ERROR,
            detail=f"velociraptor collection of {artifact_name!r} timed out after {timeout:.0f}s.",
            tool_version=tool_version,
            started_at=started_at,
            completed_at=completed_at,
        )
    if not result.ok:
        return CollectionOutcome(
            status=STATUS_ERROR,
            detail=f"velociraptor exited with code {result.returncode} collecting {artifact_name!r}: "
            f"{result.stderr.strip() or '(no stderr output)'}",
            tool_version=tool_version,
            started_at=started_at,
            completed_at=completed_at,
        )

    parsed = parse_jsonl(result.stdout)
    if not parsed.rows and parsed.malformed_count == 0:
        return CollectionOutcome(
            status=STATUS_DEGRADED,
            detail=f"velociraptor ran successfully but {artifact_name!r} produced zero result rows "
            "— the artifact may not apply to this host, or genuinely found nothing to report.",
            tool_version=tool_version,
            started_at=started_at,
            completed_at=completed_at,
        )
    if parsed.malformed_count > 0 and not parsed.rows:
        return CollectionOutcome(
            status=STATUS_ERROR,
            detail=f"velociraptor ran but produced no parseable JSONL output for {artifact_name!r} "
            f"({parsed.malformed_count} unparseable line(s)).",
            tool_version=tool_version,
            started_at=started_at,
            completed_at=completed_at,
        )

    status = STATUS_DEGRADED if parsed.malformed_count > 0 else STATUS_OK
    detail = f"Collected {len(parsed.rows)} row(s) from {artifact_name!r}."
    if parsed.malformed_count > 0:
        detail += f" {parsed.malformed_count} additional line(s) could not be parsed and were skipped."

    return CollectionOutcome(
        status=status,
        detail=detail,
        tool_version=tool_version,
        started_at=started_at,
        completed_at=completed_at,
        rows=parsed.rows,
        malformed_row_count=parsed.malformed_count,
    )
