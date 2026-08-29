"""
timeline_engine.py
-------------------
Pulls together everything built so far — the live file walk
(fat16_parser), recovered deleted files (deleted_file_recovery), and
anomaly findings (anomaly_detector) — into a single chronological
timeline of events, the way forensic timeline tools like Plaso/log2timeline
present results: one row per (file, MAC timestamp type), sorted by time.

Also provides CSV/JSON export and basic search/filter helpers.
"""

import csv
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


@dataclass
class TimelineEvent:
    timestamp: Optional[datetime]
    event_type: str          # "created" | "modified" | "accessed"
    path: str
    size: int
    deleted: bool
    severity: Optional[str]  # "LOW" | "MEDIUM" | "HIGH" | None
    anomaly_rule: Optional[str]

    def to_dict(self):
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


def _severity_for(path, anomalies_by_path):
    """A file can trip more than one rule; the timeline shows the
    highest severity found for that path."""
    hits = anomalies_by_path.get(path, [])
    if not hits:
        return None, None
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    top = max(hits, key=lambda a: order[a.severity.value])
    return top.severity.value, top.rule


def generate_timeline(live_records, deleted_records=None, anomalies=None):
    """
    live_records: list of FileRecord from fat16_parser.Fat16Parser.walk()
    deleted_records: list of RecoveredFile from DeletedFileRecovery.scan()
    anomalies: list of Anomaly from AnomalyDetector.scan() (run over live_records)
    """
    deleted_records = deleted_records or []
    anomalies = anomalies or []

    anomalies_by_path = {}
    for a in anomalies:
        anomalies_by_path.setdefault(a.path, []).append(a)

    events = []

    for r in live_records:
        if r.is_dir:
            continue
        severity, rule = _severity_for(r.path, anomalies_by_path)
        for event_type, ts in (("created", r.created),
                                ("modified", r.modified),
                                ("accessed", r.accessed)):
            if ts is None:
                continue
            events.append(TimelineEvent(
                timestamp=ts, event_type=event_type, path=r.path,
                size=r.size, deleted=False,
                severity=severity, anomaly_rule=rule,
            ))

    for rf in deleted_records:
        for event_type, ts in (("created", rf.created),
                                ("modified", rf.modified),
                                ("accessed", rf.accessed)):
            if ts is None:
                continue
            events.append(TimelineEvent(
                timestamp=ts, event_type=event_type, path=rf.path,
                size=rf.size, deleted=True,
                severity=None, anomaly_rule=None,
            ))

    events.sort(key=lambda e: e.timestamp)
    return events


# ---------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------

def export_csv(events, out_path):
    fieldnames = ["timestamp", "event_type", "path", "size",
                  "deleted", "severity", "anomaly_rule"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for e in events:
            writer.writerow(e.to_dict())
    return out_path


def export_json(events, out_path):
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump([e.to_dict() for e in events], f, indent=2)
    return out_path


# ---------------------------------------------------------------------
# Search / filter helpers — each takes a list of events, returns a
# filtered list. Designed to be chained: filter_by_path(filter_deleted(events, False), "docs")
# ---------------------------------------------------------------------

def filter_by_date_range(events, start=None, end=None):
    return [e for e in events
            if (start is None or e.timestamp >= start)
            and (end is None or e.timestamp <= end)]


def filter_by_path(events, substring):
    substring = substring.lower()
    return [e for e in events if substring in e.path.lower()]


def filter_by_event_type(events, event_type):
    return [e for e in events if e.event_type == event_type]


def filter_by_severity(events, min_severity):
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    threshold = order[min_severity]
    return [e for e in events
            if e.severity and order[e.severity] >= threshold]


def filter_deleted(events, deleted=True):
    return [e for e in events if e.deleted == deleted]


def main():
    import sys
    from fat16_parser import Fat16Parser
    from deleted_file_recovery import DeletedFileRecovery
    from anomaly_detector import AnomalyDetector

    image_path = sys.argv[1] if len(sys.argv) > 1 else "test_disk.dd"
    acquisition_time = datetime(2026, 8, 25, 12, 0, 0)

    parser = Fat16Parser(image_path)
    live_records = [r for r in parser.walk() if not r.name.startswith("$")]

    detector = AnomalyDetector(acquisition_time=acquisition_time)
    anomalies = detector.scan(live_records)

    recovery = DeletedFileRecovery(image_path)
    deleted_records = recovery.scan()

    events = generate_timeline(live_records, deleted_records, anomalies)

    print(f"Generated {len(events)} timeline events\n")
    for e in events:
        flag = f" [{e.severity}]" if e.severity else ""
        deleted_tag = " (DELETED)" if e.deleted else ""
        print(f"{e.timestamp}  {e.event_type:<9} {e.path:<20} "
              f"size={e.size:<6}{deleted_tag}{flag}")

    export_csv(events, "timeline.csv")
    export_json(events, "timeline.json")
    print("\nExported timeline.csv and timeline.json")


if __name__ == "__main__":
    main()
