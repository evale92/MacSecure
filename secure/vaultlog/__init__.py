"""Record every command run into the Obsidian vault, deduplicated.

Design rule from the operator: a run whose output is unchanged must not
create a second note. Instead the existing note's run count goes up and its
last-seen timestamp moves. Only a *different* output creates a new note, and
that note records what changed relative to the previous one.

Volatile text (timestamps, run ids, pids, durations) is stripped before
hashing, so "same result, different clock" counts as a repeat rather than a
change.
"""

from __future__ import annotations

import datetime as _dt
import difflib
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Optional

VAULT = Path.home() / "Documents" / "Obsidian Vault" / "Agent" / "Projects" / "secure" / "Runs"
INDEX = VAULT / "_index.json"

# Lines/!fragments that change every run but mean nothing for "did the result change".
_VOLATILE = [
    re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.,]?\d*"),   # timestamps
    re.compile(r"\(run id: [0-9A-Za-z]+\)"),
    re.compile(r"\(started \d{2}:\d{2}:\d{2}\)"),
    re.compile(r"— \d{2}:\d{2}:\d{2}"),
    re.compile(r"\bpid[= ]\d+", re.I),
    re.compile(r"\b\d+(\.\d+)?\s?(ms|s)\b"),                          # durations
    re.compile(r"updated \d+ day\(s\) ago"),
]


def _normalise(text: str) -> str:
    out = text
    for pat in _VOLATILE:
        out = pat.sub("«v»", out)
    return "\n".join(line.rstrip() for line in out.strip().splitlines())


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:60] or "run"


def _load_index() -> dict:
    try:
        return json.loads(INDEX.read_text())
    except (OSError, ValueError):
        return {}


def _save_index(idx: dict) -> None:
    INDEX.parent.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(json.dumps(idx, indent=2, sort_keys=True))


def record_run(label: str, argv, exit_code: int, output: str,
               vault: Optional[Path] = None) -> dict:
    """Record one run. Returns a dict describing what was written."""
    root = Path(vault) if vault else VAULT
    root.mkdir(parents=True, exist_ok=True)

    norm = _normalise(output)
    digest = hashlib.sha256(f"{label}\n{norm}".encode()).hexdigest()[:12]
    now = _dt.datetime.now().isoformat(timespec="seconds")
    cmd = " ".join(argv) if isinstance(argv, (list, tuple)) else str(argv)

    idx = _load_index()
    entry = idx.setdefault(label, {"variants": {}, "total_runs": 0})
    entry["total_runs"] += 1

    note = root / f"{_slug(label)} — {digest}.md"

    if digest in entry["variants"]:
        v = entry["variants"][digest]
        v["count"] += 1
        v["last_seen"] = now
        entry["last_variant"] = digest
        _save_index(idx)
        _rewrite_header(note, label, cmd, exit_code, v)
        return {"status": "repeat", "note": str(note), "count": v["count"], "digest": digest}

    # New output for this label — record it, and diff against the most recent
    # previous variant so the change itself is documented.
    prev = None
    prev_digest = entry.get("last_variant")
    if prev_digest and prev_digest in entry["variants"]:
        prev = entry["variants"][prev_digest]

    v = {"count": 1, "first_seen": now, "last_seen": now,
         "exit_code": exit_code, "note": note.name}
    entry["variants"][digest] = v
    entry["last_variant"] = digest
    _save_index(idx)

    body = [
        "---",
        "author: claude",
        "kind: run-log",
        f"command: {label}",
        f"digest: {digest}",
        f"first_seen: {now}",
        f"last_seen: {now}",
        "run_count: 1",
        f"exit_code: {exit_code}",
        "---",
        "",
        f"# {label}",
        "",
        f"`{cmd}`",
        "",
        f"Exit code **{exit_code}**. First seen {now}.",
        "",
    ]
    if prev is not None:
        diff = list(difflib.unified_diff(
            (prev.get("normalised") or "").splitlines(),
            norm.splitlines(),
            fromfile=f"previous ({prev['note']})", tofile="this run", lineterm="", n=2,
        ))
        body += ["## What changed since the last different result", "",
                 "```diff", *(diff[:200] or ["(no textual diff available)"]), "```", ""]
    body += ["## Output", "", "```", norm, "```", ""]

    v["normalised"] = norm
    _save_index(idx)
    note.write_text("\n".join(body))
    return {"status": "new", "note": str(note), "count": 1, "digest": digest,
            "changed_from": prev["note"] if prev else None}


def _rewrite_header(note: Path, label: str, cmd: str, exit_code: int, v: dict) -> None:
    """Bump run_count/last_seen in place; the output body is untouched."""
    if not note.exists():
        return
    text = note.read_text()
    text = re.sub(r"^run_count: .*$", f"run_count: {v['count']}", text, count=1, flags=re.M)
    text = re.sub(r"^last_seen: .*$", f"last_seen: {v['last_seen']}", text, count=1, flags=re.M)
    note.write_text(text)
