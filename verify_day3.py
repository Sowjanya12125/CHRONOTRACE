"""
verify_day3.py
---------------
Closes the loop on Day 3: rebuilds the test image (now including a
deleted file), then checks that
  1. deleted_file_recovery.py finds it, with correct metadata and
     fully recovered content, and
  2. anomaly_detector.py flags the planted timestomped file at HIGH
     severity and does NOT false-positive on anything else.
Exit code 0 = Day 3 objective met.
"""

import subprocess
import sys
from datetime import datetime

from deleted_file_recovery import DeletedFileRecovery
from anomaly_detector import AnomalyDetector
from fat16_parser import Fat16Parser

ACQUISITION_TIME = datetime(2026, 8, 25, 12, 0, 0)


def check_deleted_recovery():
    failures = []
    recovery = DeletedFileRecovery("test_disk.dd")
    found = recovery.scan()

    if len(found) != 1:
        failures.append(f"expected 1 deleted file, found {len(found)}")
        return failures

    rf = found[0]
    if rf.name != "_ECRET.TXT":
        failures.append(f"deleted file name mismatch: got {rf.name}")
    if rf.size != 67:
        failures.append(f"deleted file size mismatch: got {rf.size}, want 67")
    if not rf.content_recovered:
        failures.append("deleted file content was NOT recovered")
    elif b"deleted but its data" not in rf.content:
        failures.append("recovered content doesn't match expected text")
    if rf.created != datetime(2026, 8, 22, 15, 0, 0):
        failures.append(f"deleted file created time mismatch: got {rf.created}")

    return failures


def check_anomaly_detection():
    failures = []
    parser = Fat16Parser("test_disk.dd")
    records = [r for r in parser.walk() if not r.name.startswith("$")]

    detector = AnomalyDetector(acquisition_time=ACQUISITION_TIME)
    findings = detector.scan(records)

    hits = [f for f in findings if f.path == "/INVOICE.PDF"
            and f.rule == "modified_before_created"]
    if not hits:
        failures.append("INVOICE.PDF timestomping anomaly was NOT detected")
    elif hits[0].severity.value != "HIGH":
        failures.append(f"INVOICE.PDF anomaly severity mismatch: got {hits[0].severity.value}")

    false_positives = [f for f in findings if f.path != "/INVOICE.PDF"]
    if false_positives:
        failures.append(f"unexpected anomalies on clean files: {false_positives}")

    return failures


def main():
    print("Rebuilding test image (now with a deleted file)...")
    subprocess.run([sys.executable, "build_test_image.py"], check=True)

    failures = []
    failures += [f"[recovery] {f}" for f in check_deleted_recovery()]
    failures += [f"[anomaly]  {f}" for f in check_anomaly_detection()]

    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)

    print("\nPASSED — deleted file recovered with intact metadata and content;")
    print("timestomped file correctly flagged HIGH severity with no false positives.")


if __name__ == "__main__":
    main()
