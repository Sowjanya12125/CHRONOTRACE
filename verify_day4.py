"""
verify_day4.py
---------------
Closes the loop on Day 4/5-scope work: builds the timeline from the
test image and checks
  1. event count and chronological ordering are correct,
  2. the deleted file's events are tagged deleted=True,
  3. the anomaly-flagged file's events carry severity/rule,
  4. CSV and JSON export round-trip correctly,
  5. each search/filter helper returns the expected subset.
Exit code 0 = Day 4 objective met.
"""

import csv
import json
import subprocess
import sys
from datetime import datetime

from fat16_parser import Fat16Parser
from deleted_file_recovery import DeletedFileRecovery
from anomaly_detector import AnomalyDetector
from timeline_engine import (
    generate_timeline, export_csv, export_json,
    filter_by_date_range, filter_by_path, filter_by_event_type,
    filter_by_severity, filter_deleted,
)

ACQUISITION_TIME = datetime(2026, 8, 25, 12, 0, 0)


def build_events():
    parser = Fat16Parser("test_disk.dd")
    live = [r for r in parser.walk() if not r.name.startswith("$")]
    anomalies = AnomalyDetector(acquisition_time=ACQUISITION_TIME).scan(live)
    deleted = DeletedFileRecovery("test_disk.dd").scan()
    return generate_timeline(live, deleted, anomalies)


def main():
    print("Rebuilding test image...")
    subprocess.run([sys.executable, "build_test_image.py"], check=True)

    events = build_events()
    failures = []

    # 1. ordering
    timestamps = [e.timestamp for e in events]
    if timestamps != sorted(timestamps):
        failures.append("events are not in chronological order")
    if len(events) != 15:
        failures.append(f"expected 15 events, got {len(events)}")

    # 2. deleted file tagging
    deleted_events = [e for e in events if e.path == "/_ECRET.TXT"]
    if len(deleted_events) != 3:
        failures.append(f"expected 3 events for deleted file, got {len(deleted_events)}")
    if not all(e.deleted for e in deleted_events):
        failures.append("deleted file events not all tagged deleted=True")

    # 3. anomaly tagging
    invoice_events = [e for e in events if e.path == "/INVOICE.PDF"]
    if not all(e.severity == "HIGH" for e in invoice_events):
        failures.append("INVOICE.PDF events missing HIGH severity tag")
    if not all(e.anomaly_rule == "modified_before_created" for e in invoice_events):
        failures.append("INVOICE.PDF events missing anomaly rule name")

    # 4. export round-trip
    export_csv(events, "timeline.csv")
    export_json(events, "timeline.json")

    with open("timeline.csv", newline="", encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))
    if len(csv_rows) != len(events):
        failures.append(f"CSV row count mismatch: {len(csv_rows)} vs {len(events)}")

    with open("timeline.json", encoding="utf-8") as f:
        json_rows = json.load(f)
    if len(json_rows) != len(events):
        failures.append(f"JSON entry count mismatch: {len(json_rows)} vs {len(events)}")

    # 5. filters
    docs_only = filter_by_path(events, "docs")
    if not docs_only or not all("DOCS" in e.path for e in docs_only):
        failures.append("filter_by_path('docs') returned wrong results")

    created_only = filter_by_event_type(events, "created")
    if not created_only or not all(e.event_type == "created" for e in created_only):
        failures.append("filter_by_event_type('created') returned wrong results")

    high_only = filter_by_severity(events, "HIGH")
    if not high_only or not all(e.path == "/INVOICE.PDF" for e in high_only):
        failures.append("filter_by_severity('HIGH') returned wrong results")

    deleted_only = filter_deleted(events, True)
    if len(deleted_only) != 3 or not all(e.deleted for e in deleted_only):
        failures.append("filter_deleted(True) returned wrong results")

    ranged = filter_by_date_range(
        events, start=datetime(2026, 8, 22, 0, 0, 0), end=datetime(2026, 8, 23, 0, 0, 0))
    if not ranged or any(e.timestamp < datetime(2026, 8, 22) or
                          e.timestamp > datetime(2026, 8, 23) for e in ranged):
        failures.append("filter_by_date_range returned events outside the range")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)

    print(f"\nPASSED — {len(events)} timeline events generated, correctly ordered,")
    print("deleted/anomaly tags correct, CSV+JSON export round-trip clean,")
    print("all search/filter helpers return correct subsets.")


if __name__ == "__main__":
    main()
