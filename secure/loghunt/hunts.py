"""loghunt/hunts.py — the fixed hunts and the ndjson summariser. See the package docstring."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

from secure.loghunt._shell import run

MAX_HOURS = 72
LOG_TOOL = "/usr/bin/log"

# name -> (predicate, what a match means). Fixed; never built from input.
HUNTS = {
    "xprotect_remediator": (
        'subsystem == "com.apple.XProtectFramework.PluginAPI" AND category == "XPEvent.structured"',
        "XProtect Remediator scan reports. A line here is a scanner reporting on known malware families.",
    ),
    "xprotect_behavior": (
        'subsystem == "com.apple.XProtect" AND category == "behavior"',
        "XProtect's behavioural rules evaluating an event (macOS 15+).",
    ),
    "gatekeeper": (
        'subsystem == "com.apple.syspolicy.exec"',
        "Gatekeeper assessments of code about to run: first launches, notarization and scan results.",
    ),
    "tcc_denials": (
        'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AUTHREQ_RESULT" AND eventMessage CONTAINS "authValue=0"',
        "Privacy permission requests TCC answered with a denial.",
    ),
    "quarantine_prompts": (
        'process == "CoreServicesUIAgent" AND category == "uiagent" AND eventMessage CONTAINS "GKQuarantineResolver"',
        "The 'downloaded from the internet' first-open check on quarantined files.",
    ),
    # J-0661. Measured on this Mac 2026-09-16 over 24h: 18 matches, 17 opendirectoryd
    # credential rejections and 1 lock-screen wrong password. Broad phrases ("invalid
    # user", "authentication failed" anywhere) also matched ScreenTime and Mail account
    # noise (17 of 37), so each clause is pinned to the process or subsystem that owns it.
    "failed_logins": (
        '(subsystem == "com.apple.opendirectoryd" AND category == "auth" AND eventMessage CONTAINS "Authentication failed")'
        ' OR (process == "loginwindow" AND eventMessage CONTAINS[c] "incorrect password")'
        ' OR (process == "sshd" AND (eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "Invalid user"))'
        ' OR (process == "sudo" AND eventMessage CONTAINS "incorrect password")',
        "Local authentication failures: rejected account passwords, lock-screen, SSH and sudo attempts.",
    ),
}


@dataclass
class HuntResult:
    name: str
    meaning: str
    status: str                     # OK, ERROR or UNAVAILABLE
    detail: str = ""
    complete: bool = False          # log show printed its finished trailer
    total: int = 0
    templates: "list[dict]" = field(default_factory=list)   # {template, count, first, last, example}


def summarise(stdout: str, examples: int = 1, top: int = 15) -> "tuple[int, bool, list[dict]]":
    counts: Counter = Counter()
    first, last, example = {}, {}, {}
    complete, total = False, 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        if "finished" in event and "eventMessage" not in event:
            complete = event.get("finished") == 1
            continue
        total += 1
        template = (event.get("formatString") or event.get("eventMessage") or "")[:160]
        process = str(event.get("processImagePath") or "").rsplit("/", 1)[-1]
        key = f"{process}: {template}"
        counts[key] += 1
        stamp = str(event.get("timestamp") or "")
        first.setdefault(key, stamp)
        last[key] = stamp
        example.setdefault(key, " ".join(str(event.get("eventMessage") or "").split())[:300])
    rows = [{"template": key, "count": n, "first": first[key], "last": last[key],
             "example": example[key] if examples else ""} for key, n in counts.most_common(top)]
    return total, complete, rows


def run_hunts(hours: int = 24, names: "list[str] | None" = None, runner=run) -> "list[HuntResult]":
    if not 1 <= hours <= MAX_HOURS:
        raise ValueError(f"hours must be between 1 and {MAX_HOURS}")
    unknown = [n for n in (names or []) if n not in HUNTS]
    if unknown:
        raise ValueError(f"unknown hunt(s): {', '.join(unknown)}; known: {', '.join(HUNTS)}")
    results = []
    for name in names or list(HUNTS):
        predicate, meaning = HUNTS[name]
        shell = runner([LOG_TOOL, "show", "--style", "ndjson", "--last", f"{hours}h", "--predicate", predicate])
        if shell.returncode is None:
            status = "UNAVAILABLE" if "not found" in shell.stderr or "command not found" in shell.stderr else "ERROR"
            results.append(HuntResult(name, meaning, status, shell.stderr.strip() or "log show did not run"))
            continue
        total, complete, rows = summarise(shell.stdout)
        if shell.returncode != 0 or not complete:
            detail = (shell.stderr.strip() or f"exit {shell.returncode}")[:300]
            if not complete:
                detail = f"output ended without log's finished marker ({detail})"
            results.append(HuntResult(name, meaning, "ERROR", detail, complete, total, rows))
            continue
        results.append(HuntResult(name, meaning, "OK", "", True, total, rows))
    return results
