"""
metadata/metadata_extractor.py

Given a single file path, extract every timestamp and attribute that
matters for a forensic timeline.

MACB TIMESTAMP CAVEAT (mention this in your report - it's a real limitation
examiners deal with):
    mtime -> last content modification (same meaning everywhere)
    atime -> last read/access (same meaning everywhere)
    ctime -> Linux: metadata changed (perms/ownership) - NOT creation time
             Windows: actual creation time
    btime -> "true" creation/birth time - only reliably exposed on macOS/BSD
             via st_birthtime. Linux ext4 stores it on-disk but the plain
             stat() syscall doesn't expose it (needs statx()). We fall back
             to ctime when btime is unavailable, and that fallback should be
             documented as a known limitation, not presented as a real value.
"""

import stat
import platform
from datetime import datetime, timezone
from pathlib import Path

# `pwd` (Unix user database) only exists on POSIX systems - importing it
# unconditionally crashes on Windows. We detect the platform once here and
# use the right owner-lookup strategy for whichever OS this runs on.
IS_WINDOWS = platform.system() == "Windows"

if not IS_WINDOWS:
    import pwd
else:
    # win32security is optional (part of the pywin32 package). Without it we
    # still run correctly - we just can't resolve a friendly owner name, so
    # we fall back to a placeholder rather than crashing.
    try:
        import win32security
        HAS_PYWIN32 = True
    except ImportError:
        HAS_PYWIN32 = False


def _iso(ts: float) -> str:
    """Unix timestamp -> ISO-8601 UTC string, e.g. '2026-07-09T12:10:28.393Z'."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _get_owner(path: Path, uid: int) -> str:
    """
    Resolve the file owner. On POSIX, st_uid + the pwd database gives a
    real username. On Windows, st_uid is meaningless (always 0) - the real
    owner has to be read from the file's security descriptor instead,
    which requires pywin32. If pywin32 isn't installed, we degrade
    gracefully rather than crash.
    """
    if not IS_WINDOWS:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)

    if HAS_PYWIN32:
        try:
            sd = win32security.GetFileSecurity(
                str(path), win32security.OWNER_SECURITY_INFORMATION
            )
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            return f"{domain}\\{name}"
        except Exception:
            return "Unknown"

    return "Unknown (install pywin32 for owner info: pip install pywin32)"


def _get_permissions(mode: int) -> str:
    return stat.filemode(mode)


def extract_metadata(file_path: str) -> dict:
    """
    Returns a dict matching the `files` table schema. md5/sha256 are left
    as None here - the hashing module fills those in separately.
    """
    path = Path(file_path)

    # lstat (not stat) so a symlink is reported as itself, not followed to
    # its target - for forensics you want to know the symlink exists as an
    # artifact, not silently chase it somewhere else.
    st = path.lstat()

    is_dir = stat.S_ISDIR(st.st_mode)
    btime = getattr(st, "st_birthtime", None)  # None on most Linux systems

    return {
        "full_path": str(path.resolve()),
        "file_name": path.name,
        "parent_dir": str(path.parent.resolve()),
        "extension": path.suffix.lower() if not is_dir else "",
        "size_bytes": st.st_size,
        "is_directory": int(is_dir),
        "owner": _get_owner(path, st.st_uid),
        "permissions": _get_permissions(st.st_mode),
        "md5": None,
        "sha256": None,
        "is_deleted": 0,
        "ctime": _iso(st.st_ctime),
        "mtime": _iso(st.st_mtime),
        "atime": _iso(st.st_atime),
        "btime": _iso(btime) if btime else _iso(st.st_ctime),  # documented fallback
    }
