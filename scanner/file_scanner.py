"""
scanner/file_scanner.py

Recursively walks a target directory. For every file/directory found:
    1. extracts metadata (metadata_extractor)
    2. computes hashes (hash_generator) - files only, not directories
    3. writes the record into the database (db_manager)
    4. expands each timestamp into a timeline_event row

Deliberately decoupled from HOW the tree is produced (os.walk today).
When we add pytsk3 raw .dd image support (Day 2-3), the walk source
changes but this downstream logic doesn't.
"""

import os
from datetime import datetime, timezone

from metadata.metadata_extractor import extract_metadata
from hashing.hash_generator import hash_file
from database.db_manager import DBManager


class FileScanner:
    def __init__(self, db: DBManager, hash_files: bool = True, skip_dirs: set = None):
        self.db = db
        self.hash_files = hash_files
        self.skip_dirs = skip_dirs or {".git", "__pycache__", "node_modules", ".venv"}

    def scan(self, target_path: str) -> dict:
        started_at = datetime.now(timezone.utc).isoformat()
        self.db.set_case_info(
            case_name="FFSTG Scan",
            examiner=os.environ.get("USER", "unknown"),
            target_path=os.path.abspath(target_path),
            scan_started_at=started_at,
        )

        file_records = []
        errors = []

        for root, dirs, files in os.walk(target_path):
            # prune in-place - os.walk reads the same list object you're
            # given to decide what to recurse into; reassigning `dirs`
            # wouldn't affect that
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]

            # directories get scanned too - a folder's mtime changes when
            # something inside it is added/removed, which matters forensically
            self._process_entry(root, file_records, errors)

            for name in files:
                self._process_entry(os.path.join(root, name), file_records, errors)

        timeline_events = []
        for record in file_records:
            file_id = self.db.insert_file(record)
            timeline_events.extend(self._build_events(file_id, record))
        self.db.insert_timeline_events_bulk(timeline_events)

        completed_at = datetime.now(timezone.utc).isoformat()
        self.db.mark_scan_complete(completed_at)

        return {
            "files_scanned": len(file_records),
            "errors": len(errors),
            "error_details": errors[:20],
            "started_at": started_at,
            "completed_at": completed_at,
        }

    def _process_entry(self, path, file_records, errors):
        try:
            record = extract_metadata(path)
            if self.hash_files and not record["is_directory"]:
                hashes = hash_file(path)
                record["md5"] = hashes["md5"]
                record["sha256"] = hashes["sha256"]
            file_records.append(record)
        except (PermissionError, FileNotFoundError, OSError) as e:
            errors.append({"path": path, "error": str(e)})

    def _build_events(self, file_id, record):
        mapping = {
            "created": record["btime"],
            "modified": record["mtime"],
            "accessed": record["atime"],
            "metadata_changed": record["ctime"],
        }
        return [
            {"file_id": file_id, "event_type": etype, "event_timestamp": ts}
            for etype, ts in mapping.items()
            if ts is not None
        ]
