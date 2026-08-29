"""
fat16_builder.py
-----------------
Builds a raw .dd disk image containing a minimal but structurally correct
FAT16 file system, entirely from scratch (no external formatting tools).

This exists so Day 2 has a known-good, fully-controlled test image to
validate the pytsk3 parser against: we know exactly what files, folders,
sizes and timestamps went in, so we can assert the parser reads the same
thing back out.

FAT16 layout we build:

    [ Boot Sector (1 sector) ]
    [ Reserved sectors        ]
    [ FAT #1                  ]
    [ FAT #2                  ]
    [ Root Directory (fixed size, no cluster chain) ]
    [ Data Area (clusters, 2..N) ]

Only the pieces needed for a working, readable FAT16 volume are
implemented (8.3 names only, no LFN, single-level and one level of
subdirectory nesting).
"""

import struct
from datetime import datetime

SECTOR_SIZE = 512


def fat_time(dt: datetime) -> int:
    """Pack a datetime into FAT's 16-bit time field (2-second resolution)."""
    return (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)


def fat_date(dt: datetime) -> int:
    """Pack a datetime into FAT's 16-bit date field (year is offset from 1980)."""
    return ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day


def make_short_name(name: str) -> bytes:
    """
    Convert a filename into an 8.3 padded, space-filled 11-byte short name
    as stored in a FAT directory entry. Good enough for our test data
    (names we generate are already 8.3-safe).
    """
    if "." in name:
        base, ext = name.rsplit(".", 1)
    else:
        base, ext = name, ""
    base = base.upper()[:8].ljust(8)
    ext = ext.upper()[:3].ljust(3)
    return (base + ext).encode("ascii")


# FAT directory entry attribute flags
ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20

FAT16_EOC = 0xFFFF     # end-of-cluster-chain marker
FAT16_FREE = 0x0000
FAT16_BAD = 0xFFF7


class DirEntrySpec:
    """A file or directory queued up to be written into the image."""

    def __init__(self, name, is_dir, content=b"", created=None,
                 modified=None, accessed=None, parent="/", deleted=False):
        self.name = name
        self.is_dir = is_dir
        self.content = content
        now = datetime.now().replace(microsecond=0)
        self.created = created or now
        self.modified = modified or now
        self.accessed = accessed or now
        self.parent = parent          # "/" for root, else a directory name
        self.first_cluster = 0        # filled in during build()
        self.size = len(content)
        self.deleted = deleted        # if True, mark dir entry deleted (0xE5)
                                       # but leave FAT chain + data untouched,
                                       # exactly like a real quick-delete


class Fat16ImageBuilder:
    def __init__(self, size_bytes, sectors_per_cluster=4,
                 reserved_sectors=1, num_fats=2, root_entries=512,
                 volume_label="FORENSIC16"):
        self.size_bytes = size_bytes
        self.sectors_per_cluster = sectors_per_cluster
        self.reserved_sectors = reserved_sectors
        self.num_fats = num_fats
        self.root_entries = root_entries
        self.volume_label = volume_label[:11].ljust(11)

        self.total_sectors = size_bytes // SECTOR_SIZE
        self.bytes_per_cluster = sectors_per_cluster * SECTOR_SIZE

        # root dir occupies a fixed number of sectors, 32 bytes/entry
        self.root_dir_sectors = (root_entries * 32 + SECTOR_SIZE - 1) // SECTOR_SIZE

        # size the FAT: each cluster needs a 16-bit entry
        approx_clusters = self.total_sectors // sectors_per_cluster
        self.fat_size_sectors = max(
            1, ((approx_clusters + 2) * 2 + SECTOR_SIZE - 1) // SECTOR_SIZE
        )

        self.first_fat_sector = reserved_sectors
        self.first_root_sector = self.first_fat_sector + num_fats * self.fat_size_sectors
        self.first_data_sector = self.first_root_sector + self.root_dir_sectors

        data_sectors = self.total_sectors - self.first_data_sector
        self.total_clusters = data_sectors // sectors_per_cluster

        # cluster 0 and 1 are reserved; usable clusters start at 2
        self.fat = [FAT16_FREE] * (self.total_clusters + 2)
        self.fat[0] = 0xFFF8   # media descriptor duplicate
        self.fat[1] = FAT16_EOC

        self.data = bytearray(size_bytes)  # whole image buffer, filled as we go

        self.entries = []       # all DirEntrySpec objects, flat list
        self.dir_clusters = {}  # dir name -> first cluster (for subdirs)

    # ---------------------------------------------------------------
    # public API
    # ---------------------------------------------------------------

    def add_file(self, name, content, created=None, modified=None,
                 accessed=None, parent="/", deleted=False):
        self.entries.append(DirEntrySpec(
            name, is_dir=False, content=content,
            created=created, modified=modified, accessed=accessed,
            parent=parent, deleted=deleted,
        ))

    def add_directory(self, name, created=None, modified=None,
                       accessed=None, parent="/"):
        self.entries.append(DirEntrySpec(
            name, is_dir=True, content=b"",
            created=created, modified=modified, accessed=accessed,
            parent=parent,
        ))

    def build(self, out_path):
        self._write_boot_sector()
        self._allocate_and_write_entries()
        self._write_fats()
        with open(out_path, "wb") as f:
            f.write(self.data)
        return out_path

    # ---------------------------------------------------------------
    # internals
    # ---------------------------------------------------------------

    def _write_boot_sector(self):
        bs = bytearray(SECTOR_SIZE)
        bs[0:3] = b"\xEB\x3C\x90"                 # jmp short + nop
        bs[3:11] = b"MSWIN4.1"                     # OEM name
        struct.pack_into("<H", bs, 11, SECTOR_SIZE)
        bs[13] = self.sectors_per_cluster
        struct.pack_into("<H", bs, 14, self.reserved_sectors)
        bs[16] = self.num_fats
        struct.pack_into("<H", bs, 17, self.root_entries)
        # total sectors: use 16-bit field if it fits, else 32-bit field
        if self.total_sectors <= 0xFFFF:
            struct.pack_into("<H", bs, 19, self.total_sectors)
        else:
            struct.pack_into("<H", bs, 19, 0)
            struct.pack_into("<I", bs, 32, self.total_sectors)
        bs[21] = 0xF8                               # media descriptor: fixed disk
        struct.pack_into("<H", bs, 22, self.fat_size_sectors)
        struct.pack_into("<H", bs, 24, 63)          # sectors per track (cosmetic)
        struct.pack_into("<H", bs, 26, 255)         # heads (cosmetic)
        struct.pack_into("<I", bs, 28, 0)           # hidden sectors
        bs[36] = 0x80                                # drive number
        bs[37] = 0x00                                # reserved
        bs[38] = 0x29                                # extended boot signature
        struct.pack_into("<I", bs, 39, 0x12345678)   # volume serial number
        bs[43:54] = self.volume_label.encode("ascii")
        bs[54:62] = b"FAT16   "
        bs[510] = 0x55
        bs[511] = 0xAA
        self.data[0:SECTOR_SIZE] = bs

    def _cluster_offset(self, cluster_num):
        sector = self.first_data_sector + (cluster_num - 2) * self.sectors_per_cluster
        return sector * SECTOR_SIZE

    def _alloc_cluster_chain(self, num_clusters):
        """Find free clusters, chain them in the FAT, return list of cluster nums."""
        free = [c for c in range(2, self.total_clusters + 2) if self.fat[c] == FAT16_FREE]
        if len(free) < max(1, num_clusters):
            raise ValueError("Image too small for requested content")
        chain = free[:max(1, num_clusters)]
        for i, c in enumerate(chain):
            self.fat[c] = chain[i + 1] if i + 1 < len(chain) else FAT16_EOC
        return chain

    def _write_content_to_clusters(self, content):
        n_clusters = max(1, (len(content) + self.bytes_per_cluster - 1) // self.bytes_per_cluster)
        chain = self._alloc_cluster_chain(n_clusters if content else 1)
        for i, cluster in enumerate(chain):
            off = self._cluster_offset(cluster)
            chunk = content[i * self.bytes_per_cluster:(i + 1) * self.bytes_per_cluster]
            self.data[off:off + len(chunk)] = chunk
        return chain[0] if content else (chain[0] if chain else 0)

    def _pack_dir_entry(self, spec: DirEntrySpec):
        name = make_short_name(spec.name)
        if spec.deleted:
            # Real FAT deletion: overwrite only the first byte of the
            # short name with the 0xE5 tombstone marker. Everything else
            # (cluster chain, size, timestamps, FAT entries) is left
            # completely untouched — which is exactly why deleted FAT
            # files are so often recoverable.
            name = bytes([0xE5]) + name[1:]
        attr = ATTR_DIRECTORY if spec.is_dir else ATTR_ARCHIVE
        entry = bytearray(32)
        entry[0:11] = name
        entry[11] = attr
        entry[12] = 0
        entry[13] = 0
        struct.pack_into("<H", entry, 14, fat_time(spec.created))
        struct.pack_into("<H", entry, 16, fat_date(spec.created))
        struct.pack_into("<H", entry, 18, fat_date(spec.accessed))
        struct.pack_into("<H", entry, 20, 0)  # high cluster word, unused in FAT16
        struct.pack_into("<H", entry, 22, fat_time(spec.modified))
        struct.pack_into("<H", entry, 24, fat_date(spec.modified))
        struct.pack_into("<H", entry, 26, spec.first_cluster)
        struct.pack_into("<I", entry, 28, 0 if spec.is_dir else spec.size)
        return bytes(entry)

    def _write_dot_entries(self, dir_cluster, parent_cluster):
        """Write '.' and '..' entries at the start of a subdirectory's data."""
        now = datetime.now().replace(microsecond=0)
        dot = bytearray(32)
        dot[0:11] = b".          "
        dot[11] = ATTR_DIRECTORY
        struct.pack_into("<H", dot, 22, fat_time(now))
        struct.pack_into("<H", dot, 24, fat_date(now))
        struct.pack_into("<H", dot, 26, dir_cluster)

        dotdot = bytearray(32)
        dotdot[0:11] = b"..         "
        dotdot[11] = ATTR_DIRECTORY
        struct.pack_into("<H", dotdot, 22, fat_time(now))
        struct.pack_into("<H", dotdot, 24, fat_date(now))
        struct.pack_into("<H", dotdot, 26, parent_cluster)  # 0 = root

        off = self._cluster_offset(dir_cluster)
        self.data[off:off + 32] = dot
        self.data[off + 32:off + 64] = dotdot

    def _allocate_and_write_entries(self):
        # Pass 1: create directory clusters first so files can be
        # written into them (root dir needs no cluster: it's fixed).
        dirs = [e for e in self.entries if e.is_dir]
        files = [e for e in self.entries if not e.is_dir]

        for d in dirs:
            chain = self._alloc_cluster_chain(1)
            d.first_cluster = chain[0]
            self.dir_clusters[d.name] = chain[0]

        # write '.' and '..' now that all dir clusters are known
        for d in dirs:
            parent_cluster = 0 if d.parent == "/" else self.dir_clusters[d.parent]
            self._write_dot_entries(d.first_cluster, parent_cluster)

        # Pass 2: write file content and get first cluster
        for f in files:
            f.first_cluster = self._write_content_to_clusters(f.content)

        # Pass 3: write directory entries into their parent's directory area
        root_offset = self.first_root_sector * SECTOR_SIZE
        root_slot = 0
        # track next free slot (in 32-byte units) within each subdirectory's
        # single allocated cluster, starting after '.' and '..'
        subdir_slot = {d.name: 2 for d in dirs}

        for e in self.entries:
            packed = self._pack_dir_entry(e)
            if e.parent == "/":
                off = root_offset + root_slot * 32
                if root_slot >= self.root_entries:
                    raise ValueError("Root directory full")
                self.data[off:off + 32] = packed
                root_slot += 1
            else:
                parent_cluster = self.dir_clusters[e.parent]
                slot = subdir_slot[e.parent]
                max_slots = self.bytes_per_cluster // 32
                if slot >= max_slots:
                    raise ValueError(f"Subdirectory {e.parent} full "
                                      f"(only single-cluster dirs supported)")
                off = self._cluster_offset(parent_cluster) + slot * 32
                self.data[off:off + 32] = packed
                subdir_slot[e.parent] = slot + 1

    def _write_fats(self):
        fat_bytes = bytearray(self.fat_size_sectors * SECTOR_SIZE)
        for i, val in enumerate(self.fat):
            struct.pack_into("<H", fat_bytes, i * 2, val)
        for n in range(self.num_fats):
            off = (self.first_fat_sector + n * self.fat_size_sectors) * SECTOR_SIZE
            self.data[off:off + len(fat_bytes)] = fat_bytes
