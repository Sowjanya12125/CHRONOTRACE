"""
image_parser.py
-----------------
Filesystem-agnostic replacement for the parsing logic that used to live
directly in fat16_parser.py. The walking logic below was never actually
FAT16-specific - it only ever used pytsk3's generic constants
(TSK_FS_META_TYPE_DIR, TSK_FS_META_FLAG_UNALLOC) which work identically
across FAT, NTFS, ext, and everything else Sleuthkit supports. The ONLY
thing that needed to change to support other filesystems/images was HOW
the image gets opened - that's now delegated to disk_image.open_filesystem(),
which finds the correct partition offset automatically instead of
assuming byte 0.

fat16_parser.py now just re-exports everything from here, so any code
that does `from fat16_parser import Fat16Parser` keeps working unchanged.
"""

import datetime
import pytsk3

from disk_image import open_filesystem


class FileRecord:
    def __init__(self, path, name, is_dir, size, created, modified, accessed, inode):
        self.path = path
        self.name = name
        self.is_dir = is_dir
        self.size = size
        self.created = created
        self.modified = modified
        self.accessed = accessed
        self.inode = inode

    def __repr__(self):
        kind = "DIR " if self.is_dir else "FILE"
        return (f"[{kind}] {self.path:<30} size={self.size:<8} "
                f"created={self.created} modified={self.modified} accessed={self.accessed}")


def _to_dt(ts):
    """pytsk3 gives Unix epoch ints (0 if not set); convert to datetime or None."""
    if not ts:
        return None
    return datetime.datetime.fromtimestamp(ts).replace(tzinfo=None)


class ImageParser:
    def __init__(self, image_path):
        self.image_path = image_path
        self.img, self.fs, self.offset, self.partition_desc = open_filesystem(image_path)

    def walk(self):
        """Yield a FileRecord for every file/directory in the image."""
        records = []
        self._walk_dir(self.fs.open_dir(path="/"), "/", records)
        return records

    def _walk_dir(self, tsk_dir, current_path, records):
        for entry in tsk_dir:
            if not hasattr(entry, "info") or not entry.info.name:
                continue
            name = entry.info.name.name.decode("utf-8", errors="replace")
            if name in (".", ".."):
                continue
            if name.startswith("$"):
                # filesystem bookkeeping entries - $MBR/$FAT1/$FAT2/$OrphanFiles
                # on FAT, $MFT/$LogFile/$Bitmap/etc on NTFS - not real user
                # files, skip them the same way regardless of filesystem type
                continue

            meta = entry.info.meta
            is_dir = (meta is not None and
                      meta.type == pytsk3.TSK_FS_META_TYPE_DIR)

            if meta is not None and (meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC):
                # deleted entry - out of scope for the regular file walk;
                # see deleted_file_recovery.py for recovering these
                continue

            full_path = (current_path.rstrip("/") + "/" + name)

            if meta is not None:
                record = FileRecord(
                    path=full_path,
                    name=name,
                    is_dir=is_dir,
                    size=meta.size,
                    created=_to_dt(getattr(meta, "crtime", 0)),
                    modified=_to_dt(getattr(meta, "mtime", 0)),
                    accessed=_to_dt(getattr(meta, "atime", 0)),
                    inode=meta.addr,
                )
                records.append(record)

            if is_dir:
                try:
                    sub = entry.as_directory()
                    self._walk_dir(sub, full_path, records)
                except IOError:
                    pass  # unreadable/corrupt directory entry - skip

        return records


def main():
    import sys
    image_path = sys.argv[1] if len(sys.argv) > 1 else "test_disk.dd"

    parser = ImageParser(image_path)
    print(f"Partition used: {parser.partition_desc} (offset {parser.offset} bytes)")
    print(f"Filesystem type: {parser.fs.info.ftype}, block size: {parser.fs.info.block_size}")
    print("-" * 90)

    for record in parser.walk():
        print(record)


if __name__ == "__main__":
    main()
