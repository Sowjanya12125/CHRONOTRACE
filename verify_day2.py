"""
verify_day2.py
---------------
Closes the loop on Day 2: rebuilds the test image, parses it back with
pytsk3, and asserts every expected file/folder shows up with the right
path, size, and timestamps. Exit code 0 = Day 2 objective met.
"""

import subprocess
import sys
from datetime import datetime

from fat16_parser import Fat16Parser

EXPECTED = {
    "/README.TXT": dict(is_dir=False, size=65,
                         created=datetime(2026, 8, 20, 9, 0, 0)),
    "/NOTES.TXT": dict(is_dir=False, size=81,
                        created=datetime(2026, 8, 21, 14, 30, 0)),
    "/INVOICE.PDF": dict(is_dir=False, size=5030,
                          created=datetime(2026, 8, 22, 12, 0, 0),
                          modified=datetime(2026, 8, 19, 8, 0, 0)),  # anomaly, by design
    "/DOCS": dict(is_dir=True, size=2048),
    "/DOCS/REPORT.TXT": dict(is_dir=False, size=1900,
                              created=datetime(2026, 8, 23, 11, 0, 0)),
}


def main():
    print("Rebuilding test image...")
    subprocess.run([sys.executable, "build_test_image.py"], check=True)

    parser = Fat16Parser("test_disk.dd")
    records = {r.path: r for r in parser.walk() if not r.name.startswith("$")}

    print(f"\nFound {len(records)} entries, expected {len(EXPECTED)}\n")

    failures = []
    for path, expect in EXPECTED.items():
        if path not in records:
            failures.append(f"MISSING: {path}")
            continue
        r = records[path]
        if r.is_dir != expect["is_dir"]:
            failures.append(f"{path}: is_dir mismatch (got {r.is_dir})")
        if r.size != expect["size"]:
            failures.append(f"{path}: size mismatch (got {r.size}, want {expect['size']})")
        if "created" in expect and r.created != expect["created"]:
            failures.append(f"{path}: created mismatch (got {r.created}, want {expect['created']})")
        if "modified" in expect and r.modified != expect["modified"]:
            failures.append(f"{path}: modified mismatch (got {r.modified}, want {expect['modified']})")

    extra = set(records) - set(EXPECTED)
    if extra:
        failures.append(f"UNEXPECTED entries found: {sorted(extra)}")

    if failures:
        print("FAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)

    print("PASSED — all files, folders, sizes and timestamps round-tripped correctly.")
    print("Note: /INVOICE.PDF's modified-before-created timestamp survived intact —")
    print("that's the anomaly flag we planted for the anomaly detector to catch later.")


if __name__ == "__main__":
    main()
