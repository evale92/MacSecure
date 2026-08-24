"""
permissions.py — best-effort filesystem permission hardening for
~/.secure and everything under it (Phase 29 Stage 4: secrets hardening).

Why this exists:
    secure/config.py's own AppConfig stores three secrets in plain text
    inside ~/.secure/config.json — `virustotal_api_key`,
    `local_llm_api_key`, `smtp_password` — and ~/.secure/secure.db holds
    this Mac's entire recorded activity history (see
    docs/THREAT_MODEL.md's "what a compromise of config.json/secure.db
    would mean" table). Encrypting either file is out of scope for this
    phase (Phase 29's own instruction is to audit and harden, not add a
    new capability) — but restricting both to the owning user only is a
    small, safe, purely additive change with real value: it's the same
    baseline SSH already applies to ~/.ssh/id_rsa, using the same
    stdlib `os.chmod` call, nothing more.

Design choice:
    Both helpers are best-effort and never raise. A filesystem that
    doesn't support POSIX permission bits (some network shares, certain
    container overlays) should never crash the app over a hardening
    step that's a bonus, not a requirement for the app to function.
"""

from __future__ import annotations

import os
from pathlib import Path

# rw for owner only — used for config.json, secure.db, and secure.log.
FILE_MODE = 0o600

# rwx for owner only — used for ~/.secure itself.
DIR_MODE = 0o700


def harden_file(path: Path) -> None:
    """Best-effort: restrict `path` to owner read/write only.

    Silently does nothing if `path` doesn't exist yet or the filesystem
    doesn't support chmod — callers are expected to call this AFTER the
    file has been created/opened, not as a substitute for that.
    """
    try:
        os.chmod(path, FILE_MODE)
    except OSError:
        pass


def harden_dir(path: Path) -> None:
    """Best-effort: restrict `path` to owner read/write/execute only."""
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass
