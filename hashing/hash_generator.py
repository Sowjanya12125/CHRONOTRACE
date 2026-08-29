"""
hashing/hash_generator.py

Computes MD5 + SHA-256 for evidence integrity. Both hashes: SHA-256 is the
modern collision-resistant standard, MD5 is kept for compatibility with
legacy hash-matching databases (e.g. NSRL) that still use it.

Reads in fixed-size chunks - never loads a whole file into memory. That's
the difference between this tool working on a multi-GB disk image versus
crashing on one.
"""

import hashlib

CHUNK_SIZE = 65536  # 64 KB


def hash_file(file_path: str) -> dict:
    """
    Returns {'md5': hex, 'sha256': hex}. Returns Nones (not an exception)
    if the file can't be read - a forensic scan of thousands of files
    shouldn't crash because one is inaccessible.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                md5.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
    except (PermissionError, OSError, FileNotFoundError):
        return {"md5": None, "sha256": None}
