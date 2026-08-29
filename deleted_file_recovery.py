"""
deleted_file_recovery.py
-------------------------
Scans a FAT16 image for deleted-but-not-yet-overwritten files.

How FAT deletion actually works (and why this is possible at all):
when a file is deleted, the OS only tombstones the directory entry —
it overwrites the first byte of the 8.3 name with 0xE5 and marks the
entry unallocated. It does NOT clear the file's FAT cluster chain and
does NOT wipe the file's data. Both remain on disk, fully intact,
until something else needs those clusters and overwrites them.

pytsk3 surfaces these tombstoned entries automatically when you walk a
directory: they come back with meta.flags containing
TSK_FS_META_FLAG_UNALLOC instead of TSK_FS_META_FLAG_ALLOC, and
Sleuthkit replaces the lost first character of the name with '_' by
convention (since the real first byte was overwritten with 0xE5 and
is unrecoverable). Everything else — size, timestamps, cluster chain,
content — is usually still readable.
"""

import datetime
import pytsk3

from disk_image import open_filesystem
from image_parser import _to_dt


class RecoveredFile:
    def __init__(self, path, name, size, created, modified, accessed,
                 inode, content, content_recovered):
        self.path = path
        self.name = name
        self.size = size
        self.created = created
        self.modified = modified
        self.accessed = accessed
        self.inode = inode
        self.content = content
        self.content_recovered = content_recovered

    def __repr__(self):
        status = "content OK" if self.content_recovered else "content UNRECOVERABLE"
        return (f"[DELETED] {self.path:<30} size={self.size:<8} "
                f"created={self.created} modified={self.modified} ({status})")


class DeletedFileRecovery:
    def __init__(self, image_path):
        self.image_path = image_path
        self.img, self.fs, self.offset, self.partition_desc = open_filesystem(image_path)

    def scan(self):
        """Walk the whole tree and return RecoveredFile for every
        entry whose directory slot is marked unallocated (deleted)."""
        results = []
        self._walk("/", self.fs.open_dir(path="/"), results)
        return results

    def _walk(self, current_path, tsk_dir, results):
        for entry in tsk_dir:
            if not hasattr(entry, "info") or not entry.info.name:
                continue
            name = entry.info.name.name.decode("utf-8", errors="replace")
            if name in (".", "..") or name.startswith("$"):
                continue

            meta = entry.info.meta
            if meta is None:
                continue

            is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
            is_dir = (meta.type == pytsk3.TSK_FS_META_TYPE_DIR)
            full_path = current_path.rstrip("/") + "/" + name

            if is_deleted and not is_dir:
                results.append(self._recover_file(full_path, name, entry, meta))

            # still descend into live subdirectories to find deleted
            # files nested inside them
            if is_dir and not is_deleted:
                try:
                    self._walk(full_path, entry.as_directory(), results)
                except IOError:
                    pass

    def _recover_file(self, path, name, entry, meta):
        content = b""
        recovered = False
        try:
            content = entry.read_random(0, meta.size)
            recovered = len(content) == meta.size
        except (IOError, OSError):
            # cluster chain was reused/overwritten — metadata survives,
            # content doesn't
            recovered = False

        return RecoveredFile(
            path=path,
            name=name,
            size=meta.size,
            created=_to_dt(getattr(meta, "crtime", 0)),
            modified=_to_dt(getattr(meta, "mtime", 0)),
            accessed=_to_dt(getattr(meta, "atime", 0)),
            inode=meta.addr,
            content=content,
            content_recovered=recovered,
        )


def main():
    import sys
    image_path = sys.argv[1] if len(sys.argv) > 1 else "test_disk.dd"

    recovery = DeletedFileRecovery(image_path)
    found = recovery.scan()

    print(f"Scanned {image_path} — {len(found)} deleted file(s) found\n")
    for rf in found:
        print(rf)
        if rf.content_recovered:
            preview = rf.content[:60].decode("utf-8", errors="replace")
            print(f"    preview: {preview!r}")


if __name__ == "__main__":
    main()
