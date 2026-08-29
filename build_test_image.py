"""
build_test_image.py
--------------------
Uses fat16_builder to produce a small, known-content .dd image we can
run the pytsk3 parser against. Every file/folder here is deliberately
chosen so we can hand-verify the parser's output later.
"""

from datetime import datetime
from fat16_builder import Fat16ImageBuilder

IMAGE_PATH = "test_disk.dd"
IMAGE_SIZE = 16 * 1024 * 1024  # 16 MB — small, fast, plenty of room


def main():
    b = Fat16ImageBuilder(size_bytes=IMAGE_SIZE, volume_label="TESTDISK")

    # A couple of plain root-level files
    b.add_file(
        "readme.txt",
        b"This is a test file created for the forensic timeline generator.\n",
        created=datetime(2026, 8, 20, 9, 0, 0),
        modified=datetime(2026, 8, 20, 9, 0, 0),
        accessed=datetime(2026, 8, 25, 10, 0, 0),
    )
    b.add_file(
        "notes.txt",
        b"Case notes:\n- Suspect machine imaged 2026-08-25\n- Chain of custody form attached\n",
        created=datetime(2026, 8, 21, 14, 30, 0),
        modified=datetime(2026, 8, 24, 16, 45, 0),
        accessed=datetime(2026, 8, 25, 10, 0, 0),
    )

    # A file with a deliberately suspicious timestamp: modified BEFORE
    # created. Real forensic tools flag this as a possible sign of
    # timestamp tampering (anti-forensic timestomping). We're not
    # detecting it yet (that's a later day) — just planting it so the
    # test data is ready when we build the anomaly detector.
    b.add_file(
        "invoice.pdf",
        b"%PDF-FAKE-CONTENT-FOR-TESTING\n" + b"X" * 5000,
        created=datetime(2026, 8, 22, 12, 0, 0),
        modified=datetime(2026, 8, 19, 8, 0, 0),   # earlier than created
        accessed=datetime(2026, 8, 25, 10, 0, 0),
    )

    # A subdirectory with a file inside it, to prove nested paths work
    b.add_directory(
        "docs",
        created=datetime(2026, 8, 20, 9, 5, 0),
        modified=datetime(2026, 8, 20, 9, 5, 0),
        accessed=datetime(2026, 8, 25, 10, 0, 0),
    )
    b.add_file(
        "report.txt",
        b"Quarterly report placeholder content.\n" * 50,  # spans >1 cluster
        created=datetime(2026, 8, 23, 11, 0, 0),
        modified=datetime(2026, 8, 23, 11, 30, 0),
        accessed=datetime(2026, 8, 25, 10, 0, 0),
        parent="docs",
    )

    # A deleted file: directory entry tombstoned (0xE5), FAT chain and
    # data left untouched — the classic "just deleted, not yet
    # overwritten" case that recovery tools target.
    b.add_file(
        "secret.txt",
        b"This file was deleted but its data and metadata are still on disk.\n",
        created=datetime(2026, 8, 22, 15, 0, 0),
        modified=datetime(2026, 8, 22, 15, 10, 0),
        accessed=datetime(2026, 8, 24, 9, 0, 0),
        deleted=True,
    )

    path = b.build(IMAGE_PATH)
    print(f"Built {path} ({IMAGE_SIZE // (1024*1024)} MB FAT16 image)")


if __name__ == "__main__":
    main()
