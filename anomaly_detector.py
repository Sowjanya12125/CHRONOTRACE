"""
anomaly_detector.py
--------------------
Groundwork for the anomaly detection engine. Takes the FileRecord
objects produced by fat16_parser.py (and, soon, deleted_file_recovery.py)
and runs a set of independent rules over them. Each rule that fires
produces an Anomaly with a severity level, so later this can feed
straight into the findings database / report generator.

Designed to be extended: adding a new detection just means adding a
new function to RULES with the same signature.
"""

from datetime import datetime, timedelta
from enum import Enum


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Anomaly:
    def __init__(self, path, rule, severity: Severity, detail):
        self.path = path
        self.rule = rule
        self.severity = severity
        self.detail = detail

    def __repr__(self):
        return f"[{self.severity.value:<6}] {self.rule:<24} {self.path:<30} {self.detail}"


# ---------------------------------------------------------------------
# Individual rules. Each takes a FileRecord and the acquisition time
# (when the disk image was captured — anything after that is
# suspicious), and yields zero or more Anomaly objects.
# ---------------------------------------------------------------------

def rule_modified_before_created(record, acquisition_time):
    """Classic timestomping indicator: a file can't legitimately be
    modified before it was created."""
    if record.created and record.modified and record.modified < record.created:
        gap = record.created - record.modified
        yield Anomaly(
            record.path, "modified_before_created", Severity.HIGH,
            f"modified {record.modified} is {gap} earlier than created {record.created} "
            f"— possible timestamp tampering",
        )


def rule_accessed_before_created(record, acquisition_time):
    """A file being accessed before it existed is impossible under
    normal use — usually indicates a manipulated timestamp."""
    if record.created and record.accessed and record.accessed < record.created:
        yield Anomaly(
            record.path, "accessed_before_created", Severity.MEDIUM,
            f"accessed {record.accessed} is earlier than created {record.created}",
        )


def rule_future_dated(record, acquisition_time):
    """Any MAC timestamp after the disk was imaged shouldn't exist —
    either the system clock was wrong, or the timestamp was set
    deliberately to something implausible."""
    for label, ts in (("created", record.created),
                       ("modified", record.modified),
                       ("accessed", record.accessed)):
        if ts and ts > acquisition_time:
            yield Anomaly(
                record.path, "future_dated_timestamp", Severity.MEDIUM,
                f"{label} timestamp {ts} is after the acquisition time {acquisition_time}",
            )


def rule_identical_mac_times(record, acquisition_time):
    """All three timestamps exactly identical, down to the second, is
    unusual for anything but a fresh bulk copy — worth a low-severity
    flag to review, not a red alert on its own."""
    if record.created and record.modified and record.accessed:
        if record.created == record.modified == record.accessed:
            yield Anomaly(
                record.path, "identical_mac_times", Severity.LOW,
                f"created, modified and accessed are all exactly {record.created} "
                f"— consistent with a bulk copy/restore, worth noting",
            )


RULES = [
    rule_modified_before_created,
    rule_accessed_before_created,
    rule_future_dated,
    rule_identical_mac_times,
]


class AnomalyDetector:
    def __init__(self, acquisition_time=None):
        # default: "now" stands in for when the disk was imaged
        self.acquisition_time = acquisition_time or datetime.now()

    def scan(self, records):
        findings = []
        for record in records:
            if record.is_dir:
                continue
            for rule in RULES:
                findings.extend(rule(record, self.acquisition_time))
        return findings


def main():
    import sys
    from fat16_parser import Fat16Parser

    image_path = sys.argv[1] if len(sys.argv) > 1 else "test_disk.dd"
    # for this test image, "now" is meaningless (files are dated
    # 2026-08-2x); pin acquisition time just after the latest legit
    # timestamp in the test data so future-dating rule behaves sanely
    acquisition_time = datetime(2026, 8, 25, 12, 0, 0)

    parser = Fat16Parser(image_path)
    records = [r for r in parser.walk() if not r.name.startswith("$")]

    detector = AnomalyDetector(acquisition_time=acquisition_time)
    findings = detector.scan(records)

    print(f"Scanned {len(records)} entries — {len(findings)} anomaly finding(s)\n")
    for f in findings:
        print(f)


if __name__ == "__main__":
    main()
