# CHRONOTRACE
#FFSTG — Forensic File System Timeline Generator
#Forensic File-System Timeline & Evidence Analyzer
Digital Forensics • Incident Response • Evidence Intelligence

A Python-based digital forensics tool that scans a raw disk image (`.dd`),
builds a chronological activity timeline from file metadata, recovers
deleted files, flags timestamp anomalies with severity levels, and
produces HTML/PDF investigation reports and an interactive dashboard.

## Features

- **Metadata collection** — scans a disk image and extracts file metadata
  (name, path, size, MAC timestamps) via [pytsk3](https://github.com/py4n6/pytsk)
  (The Sleuth Kit bindings)
- **Deleted file recovery** — detects tombstoned FAT directory entries and
  recovers their content from the still-intact cluster chain where possible
- **Anomaly detection** — a pluggable rule engine (timestomping detection,
  future-dated timestamps, identical MAC times, etc.) with LOW/MEDIUM/HIGH
  severity levels
- **Timeline engine** — merges everything into one chronological timeline,
  exportable to CSV/JSON, with date-range/path/severity/type filters
- **Reports** — investigation-ready HTML and PDF reports (summary stats,
  anomaly findings, recovered files, full timeline)
- **Interactive dashboard** — Streamlit app with an uploadable disk image,
  filters, an interactive timeline chart, and severity/event-type
  breakdown charts

## Project structure

```
fat16_builder.py           FAT16 disk image builder (used to generate test data)
build_test_image.py        Builds a known-content test .dd image
fat16_parser.py             pytsk3-based metadata parser
deleted_file_recovery.py    Recovers deleted files from unallocated directory entries
anomaly_detector.py         Rule-based anomaly/severity engine
timeline_engine.py          Merges everything into one timeline + export/filter helpers
report_generator.py         HTML + PDF report generation
dashboard.py                Streamlit interactive dashboard
verify_day*.py              Automated checks for each build stage
```

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Build the test disk image (or point the tools at your own `.dd` image):

```bash
python build_test_image.py
```

Run the pipeline stages directly:

```bash
python fat16_parser.py test_disk.dd            # list files + metadata
python deleted_file_recovery.py test_disk.dd    # recover deleted files
python anomaly_detector.py test_disk.dd         # flag timestamp anomalies
python timeline_engine.py test_disk.dd          # full timeline + CSV/JSON export
python report_generator.py test_disk.dd         # writes report.html + report.pdf
```

Launch the dashboard:

```bash
streamlit run dashboard.py
```

Then either upload a `.dd` image through the sidebar, or point it at a
local path.

Run the automated checks:

```bash
python verify_day2.py
python verify_day3.py
python verify_day4.py
python verify_day6.py
```

## Notes

- The bundled test image is synthetic (built by `fat16_builder.py`), used
  to validate the pipeline against known-good data. It hasn't yet been
  tested against a real forensically-captured disk image.
- Large uploads: Streamlit defaults to a 200MB upload limit. For larger
  images, run `streamlit run dashboard.py --server.maxUploadSize=4096`
  (adjust the MB limit as needed).
