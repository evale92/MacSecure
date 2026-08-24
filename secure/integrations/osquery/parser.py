"""
integrations/osquery/parser.py — turns osqueryi's raw JSON rows into
this integration's normalized ExternalObservation shape (see
secure/integrations/base.py). Pure functions only: string/JSON in,
ExternalObservation list out — no subprocess calls, no database access,
so every rule here is directly testable with hand-built JSON text.

osquery reports every column as a string (its own convention, regardless
of the underlying SQLite column type) — every numeric field here is
explicitly coerced, defensively, rather than trusted as already-typed.
"""

from __future__ import annotations

import json
from typing import Optional

from secure.integrations.base import ExternalObservation
from secure.integrations.osquery.queries import (
    LAUNCHD,
    LISTENING_PORTS,
    PROCESS_OPEN_SOCKETS,
    PROCESSES,
    QUERIES,
)

_PROTO_NAMES = {"6": "tcp", "17": "udp"}


def _int_or_none(value) -> "Optional[int]":
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value) -> "Optional[bool]":
    if value in (None, ""):
        return None
    return str(value) in ("1", "true", "True")


def _proto_name(raw_protocol) -> str:
    return _PROTO_NAMES.get(str(raw_protocol), str(raw_protocol) if raw_protocol not in (None, "") else "unknown")


def parse_rows(stdout: str) -> "list[dict]":
    """Parse osqueryi --json output into a list of plain dicts.

    Raises ValueError on anything that isn't a JSON array of objects —
    callers (scanner.py) are responsible for catching this and
    downgrading that one query to a failure rather than letting a
    malformed response crash the whole collection pass.
    """
    data = json.loads(stdout)
    if not isinstance(data, list):
        raise ValueError("osqueryi --json output was not a JSON array")
    return data


def build_pid_name_map(process_rows: "list[dict]") -> "dict[int, str]":
    """pid -> process name, used to fill in process_name for
    process_open_sockets/listening_ports rows, which don't carry a name
    column of their own. Best-effort: a pid missing from this map (the
    owning process exited between queries, or PROCESSES itself failed)
    just leaves process_name as None on the affected observation(s) —
    never treated as a reason to drop the row entirely.
    """
    mapping: "dict[int, str]" = {}
    for row in process_rows:
        pid = _int_or_none(row.get("pid"))
        name = row.get("name")
        if pid is not None and name:
            mapping[pid] = name
    return mapping


def parse_processes(rows: "list[dict]", collected_at: str) -> "list[ExternalObservation]":
    observations = []
    for row in rows:
        path = row.get("path") or None
        name = row.get("name") or None
        identity_key = path or (f"name:{name}" if name else f"pid:{row.get('pid')}")
        observations.append(
            ExternalObservation(
                kind=PROCESSES,
                identity_key=identity_key,
                fields={
                    "pid": _int_or_none(row.get("pid")),
                    "name": name,
                    "path": path,
                    "cmdline": row.get("cmdline") or None,
                    "uid": row.get("uid") or None,
                    "parent": _int_or_none(row.get("parent")),
                },
                source_query=QUERIES[PROCESSES],
                collected_at=collected_at,
            )
        )
    return observations


def parse_process_open_sockets(
    rows: "list[dict]", collected_at: str, pid_name_map: "dict[int, str]"
) -> "list[ExternalObservation]":
    observations = []
    for row in rows:
        proto = _proto_name(row.get("protocol"))
        pid = _int_or_none(row.get("pid"))
        local_port = _int_or_none(row.get("local_port"))
        identity_key = f"{proto}:{local_port}:{pid}"
        observations.append(
            ExternalObservation(
                kind=PROCESS_OPEN_SOCKETS,
                identity_key=identity_key,
                fields={
                    "pid": pid,
                    "process_name": pid_name_map.get(pid) if pid is not None else None,
                    "proto": proto,
                    "local_address": row.get("local_address") or None,
                    "local_port": local_port,
                    "remote_address": row.get("remote_address") or None,
                    "remote_port": _int_or_none(row.get("remote_port")),
                    "family": row.get("family") or None,
                },
                source_query=QUERIES[PROCESS_OPEN_SOCKETS],
                collected_at=collected_at,
            )
        )
    return observations


def parse_listening_ports(
    rows: "list[dict]", collected_at: str, pid_name_map: "dict[int, str]"
) -> "list[ExternalObservation]":
    observations = []
    for row in rows:
        proto = _proto_name(row.get("protocol"))
        pid = _int_or_none(row.get("pid"))
        port = _int_or_none(row.get("port"))
        identity_key = f"{proto}:{port}"
        observations.append(
            ExternalObservation(
                kind=LISTENING_PORTS,
                identity_key=identity_key,
                fields={
                    "pid": pid,
                    "process_name": pid_name_map.get(pid) if pid is not None else None,
                    "proto": proto,
                    "port": port,
                    "address": row.get("address") or None,
                    "family": row.get("family") or None,
                },
                source_query=QUERIES[LISTENING_PORTS],
                collected_at=collected_at,
            )
        )
    return observations


def parse_launchd(rows: "list[dict]", collected_at: str) -> "list[ExternalObservation]":
    observations = []
    for row in rows:
        path = row.get("path") or None
        label = row.get("label") or None
        name = row.get("name") or None
        identity_key = path or (f"label:{label}" if label else f"name:{name}")
        observations.append(
            ExternalObservation(
                kind=LAUNCHD,
                identity_key=identity_key,
                fields={
                    "name": name,
                    "label": label,
                    "path": path,
                    "program": row.get("program") or None,
                    "program_arguments": row.get("program_arguments") or None,
                    "run_at_load": _bool_or_none(row.get("run_at_load")),
                    "keep_alive": _bool_or_none(row.get("keep_alive")),
                    "disabled": _bool_or_none(row.get("disabled")),
                    "username": row.get("username") or None,
                },
                source_query=QUERIES[LAUNCHD],
                collected_at=collected_at,
            )
        )
    return observations
