"""
main.py — Day 1 CLI entry point.

Usage:
    python main.py --target /path/to/scan --db case1.db
    python main.py --target /path/to/scan --no-hash
"""

import argparse
import time

from database.db_manager import DBManager
from scanner.file_scanner import FileScanner


def main():
    parser = argparse.ArgumentParser(description="FFSTG - Day 1: Metadata Collection")
    parser.add_argument("--target", required=True, help="Path to scan")
    parser.add_argument("--db", default="ffstg_case.db", help="Output SQLite database")
    parser.add_argument("--no-hash", action="store_true", help="Skip hashing (faster testing)")
    args = parser.parse_args()

    print(f"[*] Initializing case database: {args.db}")
    db = DBManager(args.db)

    scanner = FileScanner(db, hash_files=not args.no_hash)

    print(f"[*] Scanning target: {args.target}")
    t0 = time.time()
    summary = scanner.scan(args.target)
    elapsed = time.time() - t0

    print("\n=== SCAN SUMMARY ===")
    print(f"Files/dirs scanned : {summary['files_scanned']}")
    print(f"Errors encountered : {summary['errors']}")
    print(f"Time elapsed       : {elapsed:.2f}s")
    print(f"Database           : {args.db}")

    if summary["error_details"]:
        print("\nSample errors:")
        for e in summary["error_details"]:
            print(f"  - {e['path']}: {e['error']}")


if __name__ == "__main__":
    main()
