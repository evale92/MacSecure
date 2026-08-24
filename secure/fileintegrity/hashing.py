"""
fileintegrity/hashing.py — pure filesystem inspection: reading
metadata via lstat() (never stat() — a symlink is always inspected as
itself, never followed to whatever it points at) and computing a
SHA-256 hash. No database, no subprocess — this module never talks to
anything except the local filesystem.

Permission errors and other OSErrors are caught and returned as an
explicit "unreadable" marker rather than raised, or silently treated
as "the file doesn't exist" — those are different claims (see
FileMetadata's docstring and scanner.py's walk logic, which relies on
this distinction to avoid ever inferring a deletion from a permission
error).
"""

from __future__ import annotations

import hashlib
import os
import stat as stat_module
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - non-POSIX platform
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

DEFAULT_HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB
DEFAULT_MAX_HASH_BYTES = 50 * 1024 * 1024  # 50 MiB — see paths.py/analysis.py for how a
# skipped-too-large file is classified rather than silently ignored.


@dataclass
class FileMetadata:
    """A single lstat()-based snapshot of one path.

    `exists` is only True when the path itself (as a symlink or a
    regular file — see is_symlink/is_regular_file) could actually be
    inspected. `unreadable` is a THIRD state, distinct from both
    "exists" and "not exists": a real OSError (permission denied, I/O
    error) occurred and we genuinely don't know the current state.
    Callers must never treat unreadable=True as confirmation of
    absence.
    """

    path: str
    exists: bool
    is_symlink: bool = False
    is_regular_file: bool = False
    is_special: bool = False  # device/socket/fifo/etc — deliberately never hashed or tracked
    symlink_target: Optional[str] = None
    size: Optional[int] = None
    mtime: Optional[str] = None  # ISO 8601, UTC
    uid: Optional[int] = None
    owner: Optional[str] = None
    gid: Optional[int] = None
    group: Optional[str] = None
    mode: Optional[str] = None  # e.g. "0644" — stat.S_IMODE, octal, zero-padded to 4 digits
    is_executable: bool = False
    dev: Optional[int] = None
    ino: Optional[int] = None
    unreadable: bool = False
    unreadable_reason: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "hash": None,
            "size": self.size,
            "mtime": self.mtime,
            "uid": self.uid,
            "owner": self.owner,
            "gid": self.gid,
            "group_name": self.group,
            "mode": self.mode,
            "is_executable": self.is_executable,
            "is_symlink": self.is_symlink,
            "symlink_target": self.symlink_target,
            "dev": self.dev,
            "ino": self.ino,
        }


def _lookup_owner(uid: int) -> Optional[str]:
    if pwd is None:
        return None
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return None


def _lookup_group(gid: int) -> Optional[str]:
    if grp is None:
        return None
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OSError):
        return None


def read_metadata(path: str) -> FileMetadata:
    """lstat() a path. FileNotFoundError -> exists=False (a confirmed,
    genuine absence). Any OTHER OSError (permission denied, I/O error,
    NotADirectoryError from a race, etc.) -> unreadable=True, exists
    left False — "we tried to look and couldn't", never conflated with
    "confirmed absent".
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return FileMetadata(path=path, exists=False)
    except OSError as exc:
        return FileMetadata(path=path, exists=False, unreadable=True, unreadable_reason=str(exc))

    is_symlink = stat_module.S_ISLNK(st.st_mode)
    is_regular = stat_module.S_ISREG(st.st_mode)
    is_dir = stat_module.S_ISDIR(st.st_mode)
    is_special = not (is_symlink or is_regular or is_dir)

    symlink_target = None
    if is_symlink:
        try:
            symlink_target = os.readlink(path)
        except OSError as exc:
            return FileMetadata(
                path=path,
                exists=True,
                is_symlink=True,
                unreadable=True,
                unreadable_reason=str(exc),
            )

    mode = format(stat_module.S_IMODE(st.st_mode), "04o")
    is_executable = is_regular and bool(st.st_mode & 0o111)

    return FileMetadata(
        path=path,
        exists=True,
        is_symlink=is_symlink,
        is_regular_file=is_regular,
        is_special=is_special,
        symlink_target=symlink_target,
        size=st.st_size,
        mtime=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        uid=st.st_uid,
        owner=_lookup_owner(st.st_uid),
        gid=st.st_gid,
        group=_lookup_group(st.st_gid),
        mode=mode,
        is_executable=is_executable,
        dev=st.st_dev,
        ino=st.st_ino,
    )


def compute_sha256(
    path: str,
    max_bytes: int = DEFAULT_MAX_HASH_BYTES,
    chunk_size: int = DEFAULT_HASH_CHUNK_SIZE,
) -> "tuple[Optional[str], Optional[str]]":
    """Returns (hash_hex, skipped_reason).

    skipped_reason is None on success, "too_large" if the file exceeds
    max_bytes (checked via a cheap os.path.getsize() BEFORE reading —
    never by reading up to the limit and giving up partway), or
    "unreadable" if opening/reading raised OSError partway through
    (e.g. a permissions change or the file vanishing mid-read).
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None, "unreadable"

    if size > max_bytes:
        return None, "too_large"

    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError:
        return None, "unreadable"

    return hasher.hexdigest(), None
