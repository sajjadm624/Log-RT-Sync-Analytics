#!/usr/bin/env python3
"""
backfill_analytics.py
─────────────────────
Reads log files already on disk (BASE_LOG_DIR) and populates the
analytics DB with historical line counts, file counts, and unique
MSISDN counts — without re-processing anything that already exists.

Safe to run multiple times: uses INSERT OR IGNORE so existing rows
are never overwritten or double-counted.

Usage:
    python3 backfill_analytics.py

Or for a specific date only:
    python3 backfill_analytics.py --date 2026-03-11

Or a dry-run (print what would be inserted, touch nothing):
    python3 backfill_analytics.py --dry-run
"""

import os
import re
import sqlite3
import argparse
import time
import sys
from datetime import datetime, timezone
from collections import defaultdict

# ── Config (mirrors log-receiver.py env vars) ─────────────────────────────────
ANALYTICS_DB  = os.getenv('ANALYTICS_DB',  '/app/log-shipper/analytics.db')
BASE_LOG_DIR  = os.getenv('BASE_LOG_DIR',  '/app/log/access-log-terminal/')
DB_TIMEOUT    = int(os.getenv('DB_TIMEOUT', '30'))

# ── MSISDN regex (same as receiver) ───────────────────────────────────────────
MSISDN_PAT = re.compile(r'(?:\\x22|")msisdn(?:\\x22|"):(?:\\x22|")(\d{7,15})')

# ── Filename parser ────────────────────────────────────────────────────────────
# MyGP_accessLog_26031101_00-19_10-10-21-44.log
#                YYMMDDII HH MM-EE  SERVER-IP
FNAME_PAT = re.compile(
    r'MyGP_accessLog_(\d{2})(\d{2})(\d{2})(\d{2})_(\d{2})-(\d{2})_(.+)\.log$'
)

def parse_filename(fname):
    """
    Returns (date_hour_str, server_ip_dashed) or None if not a log file.
    date_hour_str: "YYYY-MM-DD HH"
    """
    m = FNAME_PAT.match(fname)
    if not m:
        return None
    yy, mm, dd, hh = m.group(1), m.group(2), m.group(3), m.group(4)
    server_ip = m.group(7)  # already dash-separated in filename
    date_hour = f"20{yy}-{mm}-{dd} {hh}"
    return date_hour, server_ip


def discover_files(base_dir, date_filter=None):
    """
    Walk BASE_LOG_DIR and return list of (filepath, date_hour, server_ip).
    Optionally filter to a single date string "YYYY-MM-DD".
    """
    files = []
    if not os.path.isdir(base_dir):
        print(f"ERROR: BASE_LOG_DIR not found: {base_dir}", file=sys.stderr)
        sys.exit(1)

    for server_dir in sorted(os.listdir(base_dir)):
        server_path = os.path.join(base_dir, server_dir)
        if not os.path.isdir(server_path):
            continue
        for fname in sorted(os.listdir(server_path)):
            parsed = parse_filename(fname)
            if parsed is None:
                continue
            date_hour, server_ip = parsed
            if date_filter and not date_hour.startswith(date_filter):
                continue
            files.append((os.path.join(server_path, fname), date_hour, server_ip))

    return files


def already_backfilled(conn, date_hour, server_ip):
    """True if a non-zero row already exists for this (date_hour, server_ip)."""
    row = conn.execute(
        "SELECT line_count FROM hourly_stats WHERE date_hour=? AND server_ip=?",
        (date_hour, server_ip)
    ).fetchone()
    return row is not None and row[0] > 0


def process_file(filepath):
    """
    Read a log file and return (line_count, unique_msisdns_set).
    Streams line-by-line — constant memory regardless of file size.
    """
    line_count  = 0
    msisdn_set  = set()

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line:
                    continue
                line_count += 1
                for msisdn in MSISDN_PAT.findall(line):
                    msisdn_set.add(msisdn)
    except OSError as e:
        print(f"  WARNING: could not read {filepath}: {e}", file=sys.stderr)

    return line_count, msisdn_set


def upsert_hourly(conn, date_hour, server_ip, line_count, file_count, unique_msisdns):
    """
    Python 3.6-safe upsert (no ON CONFLICT DO UPDATE).
    INSERT OR IGNORE creates the row if missing, then UPDATE increments.
    We use absolute values (not += ) because this is a backfill —
    the row was either absent (INSERT just created it at 0) or already
    had data from the live receiver (we skip those via already_backfilled).
    """
    conn.execute(
        """INSERT OR IGNORE INTO hourly_stats
           (date_hour, server_ip, line_count, file_count, unique_msisdns)
           VALUES (?, ?, 0, 0, 0)""",
        (date_hour, server_ip)
    )
    conn.execute(
        """UPDATE hourly_stats
           SET line_count     = line_count     + ?,
               file_count     = file_count     + ?,
               unique_msisdns = unique_msisdns + ?
           WHERE date_hour = ? AND server_ip = ?""",
        (line_count, file_count, unique_msisdns, date_hour, server_ip)
    )


def flush_daily(conn, date, server_ip, line_count, unique_msisdns):
    conn.execute(
        """INSERT OR IGNORE INTO daily_stats
           (date, server_ip, line_count, unique_msisdns)
           VALUES (?, ?, 0, 0)""",
        (date, server_ip)
    )
    conn.execute(
        """UPDATE daily_stats
           SET line_count     = line_count     + ?,
               unique_msisdns = unique_msisdns + ?
           WHERE date = ? AND server_ip = ?""",
        (line_count, unique_msisdns, date, server_ip)
    )


def main():
    parser = argparse.ArgumentParser(description='Backfill analytics DB from on-disk log files.')
    parser.add_argument('--date',    help='Only backfill this date, e.g. 2026-03-11')
    parser.add_argument('--dry-run', action='store_true', help='Print plan without writing anything')
    parser.add_argument('--force',   action='store_true',
                        help='Re-process files even if hourly_stats row already has data')
    args = parser.parse_args()

    print("=" * 60)
    print("  MyGP Analytics Backfill")
    print(f"  DB:      {ANALYTICS_DB}")
    print(f"  LOG DIR: {BASE_LOG_DIR}")
    if args.date:
        print(f"  Filter:  {args.date} only")
    if args.dry_run:
        print("  Mode:    DRY RUN (no writes)")
    print("=" * 60)

    # ── Discover files ────────────────────────────────────────────────────────
    print("\nScanning log directory…", end=' ', flush=True)
    files = discover_files(BASE_LOG_DIR, date_filter=args.date)
    print(f"found {len(files)} log files")

    if not files:
        print("Nothing to backfill.")
        return

    total_size_mb = sum(os.path.getsize(f[0]) / 1e6 for f in files)
    print(f"Total data to read: {total_size_mb:.0f} MB across "
          f"{len(set(f[1][:10] for f in files))} dates, "
          f"{len(set(f[2] for f in files))} servers\n")

    if args.dry_run:
        print("DRY RUN — files that would be processed:")
        for fp, dh, srv in files:
            size_mb = os.path.getsize(fp) / 1e6
            print(f"  {dh}  {srv:<20}  {size_mb:6.1f} MB  {os.path.basename(fp)}")
        print(f"\nTotal: {len(files)} files, {total_size_mb:.0f} MB")
        return

    # ── Connect to DB ─────────────────────────────────────────────────────────
    conn = sqlite3.connect(ANALYTICS_DB, timeout=DB_TIMEOUT)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    # ── Process files ──────────────────────────────────────────────────────────
    t_start    = time.time()
    skipped    = 0
    processed  = 0
    total_lines = 0

    # Accumulate per-day unique MSISDNs in memory (one set per date+server)
    # Cleared after each date to keep RAM low
    daily_msisdns = defaultdict(set)   # key: (date, server_ip)
    current_date  = None

    for i, (filepath, date_hour, server_ip) in enumerate(files):
        date = date_hour[:10]  # "YYYY-MM-DD"
        fname = os.path.basename(filepath)
        size_mb = os.path.getsize(filepath) / 1e6

        # Flush daily totals when date rolls over
        if current_date and date != current_date:
            print(f"\n  → Flushing daily totals for {current_date}…")
            for (d, srv), mset in daily_msisdns.items():
                flush_daily(conn, d, srv,
                            line_count=0,     # already counted in hourly
                            unique_msisdns=len(mset))
            conn.commit()
            daily_msisdns.clear()

        current_date = date

        # Skip check
        if not args.force and already_backfilled(conn, date_hour, server_ip):
            print(f"  SKIP  {date_hour}  {server_ip:<20}  (already has data)")
            skipped += 1
            continue

        # Progress
        elapsed = time.time() - t_start
        pct = (i + 1) / len(files) * 100
        sys.stdout.write(
            f"\r  [{i+1:3d}/{len(files)}]  {pct:5.1f}%  "
            f"{date_hour}  {server_ip:<20}  {size_mb:6.1f} MB  "
            f"elapsed {elapsed:.0f}s   "
        )
        sys.stdout.flush()

        line_count, msisdn_set = process_file(filepath)
        unique_msisdns = len(msisdn_set)

        # Accumulate into daily set
        daily_msisdns[(date, server_ip)].update(msisdn_set)

        upsert_hourly(conn, date_hour, server_ip,
                      line_count=line_count,
                      file_count=1,
                      unique_msisdns=unique_msisdns)

        processed   += 1
        total_lines += line_count

    # Flush final date
    if daily_msisdns:
        print(f"\n\n  → Flushing daily totals for {current_date}…")
        for (d, srv), mset in daily_msisdns.items():
            flush_daily(conn, d, srv, line_count=0, unique_msisdns=len(mset))

    conn.commit()
    conn.close()

    elapsed = time.time() - t_start
    print(f"\n{'=' * 60}")
    print(f"  Done in {elapsed:.1f}s")
    print(f"  Files processed : {processed}")
    print(f"  Files skipped   : {skipped}  (already had data)")
    print(f"  Lines indexed   : {total_lines:,}")
    print(f"  Speed           : {total_lines/elapsed:,.0f} lines/sec")
    print(f"{'=' * 60}")
    print("\nVerify with:")
    print(f"  curl http://10.10.23.212:8000/stats/storage | python3 -m json.tool")
    print(f"  curl 'http://10.10.23.212:8000/stats?hours=48' | python3 -m json.tool\n")


if __name__ == '__main__':
    main()
