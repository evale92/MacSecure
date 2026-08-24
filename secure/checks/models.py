"""
checks/models.py — shared types every posture check returns.

Keeping the result shape identical across all checks means the CLI,
the GUI, and the storage code only need to know about `CheckResult`
once, instead of every check inventing its own return type.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CheckStatus(str, Enum):
    """The three results a posture check can report.

    There's no "couldn't determine" status on purpose, even though a
    few checks genuinely can't get a definitive answer without sudo
    (which this package never uses — see the package docstring). Those
    checks report WARNING and say exactly why in `message`, rather
    than inventing a fourth status the CLI/GUI would also have to
    handle.
    """

    PASS = "PASS"
    WARNING = "WARNING"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    """The outcome of one posture check.

    `remediation` is the plain-English "what to do about it" — left
    as an empty string when status is PASS (there's nothing to do).
    """

    name: str
    status: CheckStatus
    message: str
    remediation: str = ""
