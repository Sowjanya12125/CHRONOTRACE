"""
disk_image.py
--------------
Shared helper for opening a raw disk image and locating its filesystem,
regardless of partitioning scheme (unpartitioned raw volume, MBR, or GPT)
or filesystem type (FAT12/16/32, NTFS, ext, etc).

WHY THIS EXISTS: the original fat16_parser.py assumed the filesystem
starts at byte 0 - true for a bare, unpartitioned FAT16 image (like
test_disk.dd), but false for a real disk image like evidence.dd, which
is GPT-partitioned with NTFS inside one of its partitions. pytsk3 can
read either kind of image just fine, but it needs to be told the correct
byte offset to start reading the filesystem from - and that offset has
to be read out of the image's own partition table, not guessed or
hardcoded, since it differs per image.
"""

import pytsk3


class UnsupportedImageError(Exception):
    """Raised when no readable filesystem could be found anywhere in
    the image - neither inside a partition table nor as a raw volume."""
    pass


def open_filesystem(image_path):
    """
    Returns (img, fs, offset_bytes, description) for the given raw disk
    image. Tries, in order:

      1. Read the image as a partitioned disk (pytsk3.Volume_Info handles
         BOTH MBR and GPT transparently - it auto-detects which one is
         present). Collect every partition that pytsk3 can actually open
         as a filesystem, skipping bookkeeping entries (the partition
         table itself, unallocated space). A real disk image usually has
         more than one *readable* partition (e.g. a small EFI System
         Partition alongside the main NTFS volume) - we pick the LARGEST
         one, since that's reliably the main data partition rather than
         a small system/reserved partition that happens to also mount.

      2. If there's no partition table at all (OSError from Volume_Info),
         fall back to treating the whole image as one unpartitioned
         filesystem starting at byte 0 - this is what a bare FAT16 test
         image like test_disk.dd looks like.

    Raises UnsupportedImageError if neither approach finds anything
    pytsk3 recognizes as a filesystem.
    """
    img = pytsk3.Img_Info(image_path)
    candidates = []  # (partition_length_sectors, offset_bytes, fs, description)

    try:
        volume = pytsk3.Volume_Info(img)
        for part in volume:
            desc = part.desc.decode(errors="replace") if part.desc else ""
            lowered = desc.lower()

            if part.len <= 0:
                continue
            # skip the partition-table bookkeeping entries themselves -
            # these show up as pseudo-partitions in pytsk3's listing but
            # don't contain a filesystem
            if any(marker in lowered for marker in
                   ("unallocated", "guid partition table", "safety table", "primary table")):
                continue

            offset_bytes = part.start * 512  # pytsk3 reports partition start in 512-byte sectors
            try:
                fs = pytsk3.FS_Info(img, offset=offset_bytes)
            except Exception:
                # this partition isn't a filesystem pytsk3 recognizes
                # (e.g. a Microsoft Reserved Partition has no filesystem
                # at all) - not an error, just keep looking
                continue

            candidates.append((part.len, offset_bytes, fs, desc or f"partition @ sector {part.start}"))
    except OSError:
        # no partition table present at all - not an error, just means
        # this might be a raw unpartitioned volume (attempt 2, below)
        pass

    if candidates:
        # largest readable partition wins - this is almost always the
        # real data volume, as opposed to a small EFI System Partition
        # or recovery partition that also happens to be readable
        candidates.sort(key=lambda c: c[0], reverse=True)
        _, offset_bytes, fs, desc = candidates[0]
        return img, fs, offset_bytes, desc

    try:
        fs = pytsk3.FS_Info(img, offset=0)
        return img, fs, 0, "unpartitioned raw filesystem"
    except Exception as e:
        raise UnsupportedImageError(
            f"Could not find a recognizable filesystem in {image_path} "
            f"(checked partition table and raw offset 0): {e}"
        )
