"""
fat16_parser.py
----------------
Kept for backward compatibility only. The actual parsing logic is now
filesystem-agnostic (works on NTFS/ext/etc, not just FAT16) and lives in
image_parser.py. This module just re-exports the same names under their
original names, so existing code - dashboard.py, anomaly_detector.py,
timeline_engine.py, and anything you wrote yourself - keeps working
without any changes: `from fat16_parser import Fat16Parser` still works
exactly as before, it just now handles more filesystem types under the hood.
"""

from image_parser import ImageParser, FileRecord, _to_dt

Fat16Parser = ImageParser


def main():
    from image_parser import main as _main
    _main()


if __name__ == "__main__":
    main()
