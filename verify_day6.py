"""
verify_day6.py
---------------
Closes the loop on Day 6: rebuilds the test image, generates both
reports, and checks
  1. both files exist and are non-trivially sized,
  2. the PDF's extracted text contains every key finding (anomaly file,
     severity, rule, deleted file name, all live file names),
  3. the HTML report contains the same, plus renders valid-looking
     table markup for each section.
Exit code 0 = Day 6 objective met.
"""

import subprocess
import sys
from datetime import datetime

from pypdf import PdfReader

from fat16_parser import Fat16Parser
from deleted_file_recovery import DeletedFileRecovery
from anomaly_detector import AnomalyDetector
from timeline_engine import generate_timeline
from report_generator import generate_html_report, generate_pdf_report

ACQUISITION_TIME = datetime(2026, 8, 25, 12, 0, 0)

EXPECTED_STRINGS = [
    "INVOICE.PDF", "HIGH", "modified_before_created",
    "_ECRET.TXT", "README.TXT", "NOTES.TXT", "DOCS/REPORT.TXT",
    "Recovered", "15",  # event count
]


def main():
    print("Rebuilding test image...")
    subprocess.run([sys.executable, "build_test_image.py"], check=True)

    parser = Fat16Parser("test_disk.dd")
    live_records = [r for r in parser.walk() if not r.name.startswith("$")]
    anomalies = AnomalyDetector(acquisition_time=ACQUISITION_TIME).scan(live_records)
    deleted_records = DeletedFileRecovery("test_disk.dd").scan()
    events = generate_timeline(live_records, deleted_records, anomalies)

    generate_html_report(events, anomalies, deleted_records, "test_disk.dd", "report.html")
    generate_pdf_report(events, anomalies, deleted_records, "test_disk.dd", "report.pdf")

    failures = []

    with open("report.html", encoding="utf-8") as f:
        html_text = f.read()
    if len(html_text) < 1000:
        failures.append("HTML report suspiciously small")
    for s in EXPECTED_STRINGS:
        if s not in html_text:
            failures.append(f"HTML report missing expected content: {s!r}")
    for tag in ["<table", "Anomaly Findings", "Recovered Deleted Files", "Full Timeline"]:
        if tag not in html_text:
            failures.append(f"HTML report missing section/tag: {tag!r}")

    reader = PdfReader("report.pdf")
    if len(reader.pages) < 2:
        failures.append(f"PDF report has too few pages: {len(reader.pages)}")
    pdf_text = "".join(p.extract_text() for p in reader.pages)
    for s in EXPECTED_STRINGS:
        if s not in pdf_text:
            failures.append(f"PDF report missing expected content: {s!r}")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)

    print(f"\nPASSED — HTML report ({len(html_text)} bytes) and PDF report "
          f"({len(reader.pages)} pages) both generated with all expected "
          f"findings present.")


if __name__ == "__main__":
    main()
