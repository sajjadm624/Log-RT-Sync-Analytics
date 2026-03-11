# 📊 MyGP Log Shipping & Analytics System

> Real-time nginx log collection, centralisation, and analytics across 21 application servers — no message broker, no cloud dependency, two Python files.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
  - [Log Shipper](#log-shipper-log-shipperpy)
  - [Log Terminal](#log-terminal-log-receiverpy)
- [Analytics Pipeline](#analytics-pipeline)
- [Dashboard](#dashboard)
- [Gunicorn Worker Count](#gunicorn-worker-count)
- [Configuration](#configuration)
- [Deployment](#deployment)
  - [Terminal Setup](#terminal-setup)
  - [Shipper Setup](#shipper-setup)
- [Backfilling Historical Data](#backfilling-historical-data)
- [Operations](#operations)

---

## Overview

The MyGP log pipeline ships nginx access logs from **21 source servers** (`10.10.21.x`) to a central **terminal** (`10.10.23.212:8000`) in real time. On arrival, logs are written to disk and analysed for subscriber activity (MSISDNs), with results served through a live web dashboard.

| | |
|---|---|
| **Source servers** | 21 × application servers (`10.10.21.x`) |
| **Terminal** | `10.10.23.212:8000` |
| **Stack** | Python 3.6 · Flask · Gunicorn · SQLite |
| **Log format** | nginx access log with embedded `\x22`-encoded JSON |
| **Dashboard** | `http://10.10.23.212:8000/dashboard` |
| **Gunicorn workers** | 1 (see [Gunicorn Worker Count](#gunicorn-worker-count)) |

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────────┐
  │  SOURCE SERVER  (×21,  10.10.21.x)                          │
  │                                                             │
  │  nginx ──writes──► .log file                                │
  │                        │                                    │
  │  log-shipper.py ◄─tails┘                                   │
  │       │  pending_fragment buffer  (handles split lines)     │
  │       │  batch accumulates  (≤1 000 lines  or  ≤10 s)      │
  │       ▼                                                     │
  │  HTTP POST /upload ────────────────────────────────────►    │
  └─────────────────────────────────────────────────────────────┘
                            │
            private network │  JSON  { server_ip, lines[] }
                            ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  TERMINAL  (10.10.23.212:8000)                              │
  │                                                             │
  │  Gunicorn  (1 worker, --preload)                            │
  │       │                                                     │
  │       ├─① _merge_continuations()   reassemble split lines  │
  │       ├─② write to disk            BASE_LOG_DIR/<ip>/*.log │
  │       ├─③ extract MSISDNs          in-memory Python sets   │
  │       └─④ flush counts             SQLite analytics.db     │
  │                                                             │
  │  Browser ◄──── GET /dashboard  (SVG charts, refresh 60 s)  │
  └─────────────────────────────────────────────────────────────┘
```

---

## Components

### Log Shipper (`log-shipper.py`)

Runs as a daemon on every source server. Tails nginx log files and POSTs batches to the terminal.

#### How it works

**1. File discovery**
Uses `watchdog` (Linux inotify) to detect new and modified `.log` files in `LOG_DIR`. nginx rotates files every 20 minutes:

```
MyGP_accessLog_YYMMDDHHII_SS-EE_SERVERIP.log
```

**2. Pending fragment buffer**

nginx's `log_format` embeds a JSON blob per request. If a User-Agent or URL contains a literal newline character, nginx splits one logical log entry across two physical lines. The shipper holds any incomplete line in a `_pending_fragment` buffer and prepends it to the next `readline()` result, ensuring only complete records enter the batch queue.

**3. Batching**

Lines accumulate in memory until either condition is met first:
- `BATCH_SIZE` lines are buffered *(default: 1 000)*, or
- `BATCH_INTERVAL` seconds have elapsed *(default: 10 s)*

**4. HTTP delivery**

```
POST http://10.10.23.212:8000/upload
Content-Type: application/json

{ "server_ip": "10.10.21.44", "lines": ["line1", "line2", ...] }
```

Failed POSTs are retried up to `MAX_RETRIES` times with `RETRY_DELAY` seconds between attempts. After all retries are exhausted the batch is discarded to prevent unbounded memory growth.

---

### Log Terminal (`log-receiver.py`)

Flask application served by Gunicorn. Receives all batches, writes logs to disk, runs analytics, and serves the dashboard.

#### HTTP Routes

| Route | Method | Description |
|---|---|---|
| `/upload` | POST | Main ingestion endpoint. Triggers the full ingest pipeline. |
| `/stats` | GET | JSON analytics data. Accepts `?hours=N&days=N`. |
| `/stats/storage` | GET | DB file size, row counts, RAM usage. |
| `/dashboard` | GET | Self-contained HTML analytics dashboard. |
| `/health` | GET | Liveness probe — returns `OK`. |

#### Ingest pipeline (per batch)

```
POST /upload
  │
  ├─ 1. Parse JSON  →  extract server_ip + lines[]
  ├─ 2. _merge_continuations()  →  reassemble any split lines
  ├─ 3. Append to disk  →  BASE_LOG_DIR/<server_ip>/MyGP_accessLog_...log
  ├─ 4. record_analytics()  →  extract MSISDNs, write counts to SQLite
  └─ 5. Return HTTP 200
```

#### On-disk file layout

```
BASE_LOG_DIR/
  10.10.21.44/
    MyGP_accessLog_26031100_00-19_10-10-21-44.log
    MyGP_accessLog_26031100_20-39_10-10-21-44.log
    MyGP_accessLog_26031100_40-59_10-10-21-44.log
    ...
  10.10.21.45/
    ...
```

Files are **append-only**. A terminal restart reopens the same file and continues appending — no data is lost or duplicated.

> **Note:** Directory names use dots (`10.10.21.44/`) while filenames use dashes (`..._10-10-21-44.log`). The DB always stores server IPs with dots.

---

## Analytics Pipeline

Analytics are extracted **inline during `/upload`** — no cron jobs, no background threads, no separate workers.

### MSISDN extraction

nginx hex-encodes double quotes as `\x22`. The MSISDN lives in the `msisdn` JSON field. The extraction regex handles both encodings:

```python
msisdn_pat = re.compile(r'(?:\\x22|")msisdn(?:\\x22|"):(?:\\x22|")(\d{7,15})')
```

> **Privacy:** Individual MSISDNs are **never written to disk**. They are held in in-memory Python `set` objects and discarded after their rolling window expires. Only the final integer count is persisted to SQLite.

### In-memory deduplication

| Set | Key format | Rolling window |
|---|---|---|
| `_msisdn_hour` | `"YYYY-MM-DD HH"` | 26 hours (`MSISDN_HOUR_WINDOW`) |
| `_msisdn_day` | `"YYYY-MM-DD"` | 2 days (`MSISDN_DAY_WINDOW`) |

### Accurate MSISDN counting with 1 worker

With **1 Gunicorn worker**, all batches from all 21 servers pass through a single process that holds a single authoritative deduplication set. This gives **exact unique counts** matching Kibana.

> With 2+ workers, each worker holds its own set. The same subscriber's requests may land on different workers, causing independent counts that inflate totals when summed. Running `-w 1` eliminates this entirely.

### SQLite schema

```sql
-- Primary analytics table: one row per (hour × server)
CREATE TABLE hourly_stats (
  date_hour       TEXT,   -- "YYYY-MM-DD HH"
  server_ip       TEXT,   -- "10.10.21.44"  (always dots, never dashes)
  line_count      INTEGER DEFAULT 0,
  file_count      INTEGER DEFAULT 0,
  unique_msisdns  INTEGER DEFAULT 0,
  PRIMARY KEY (date_hour, server_ip)
);

-- Rolled-up daily totals
CREATE TABLE daily_stats (
  date            TEXT,
  server_ip       TEXT,   -- "10.10.21.44"
  line_count      INTEGER DEFAULT 0,
  unique_msisdns  INTEGER DEFAULT 0,
  PRIMARY KEY (date, server_ip)
);

-- Per-worker accurate MSISDN totals (keyed by hour/day, not server)
-- /stats uses COALESCE(hourly_unique, SUM(hourly_stats)) for accuracy
CREATE TABLE hourly_unique (
  date_hour       TEXT PRIMARY KEY,
  unique_msisdns  INTEGER DEFAULT 0
);
CREATE TABLE daily_unique (
  date            TEXT PRIMARY KEY,
  unique_msisdns  INTEGER DEFAULT 0
);

-- Deduplication guard (auto-purged after FILES_SEEN_DAYS days)
CREATE TABLE files_seen (
  date_hour   TEXT,
  server_ip   TEXT,
  filename    TEXT,
  PRIMARY KEY (date_hour, server_ip, filename)
);

-- Internal metadata
CREATE TABLE db_meta (key TEXT PRIMARY KEY, value TEXT);
```

### DB size projection

| Table | Growth | 1 year | 5 years |
|---|---|---|---|
| `hourly_stats` | ~35 KB/day | ~13 MB | ~65 MB |
| `daily_stats` | ~1.4 KB/day | <1 MB | <3 MB |
| `hourly_unique` / `daily_unique` | ~1 KB/day | <0.5 MB | ~2 MB |
| `files_seen` | auto-purged (7 d cap) | ~5 MB | ~5 MB |
| **Total** | | **~18 MB** | **~70 MB** |

---

## Dashboard

Accessible at **`http://10.10.23.212:8000/dashboard`**

Self-contained HTML page (~70 KB, inline JS + SVG). Zero external CDN dependencies — works fully air-gapped.

### Tabs

| Tab | Contents |
|---|---|
| **Overview** | Log lines/hour · Unique MSISDNs/hour · Active servers/hour · Files/hour. All 24 hours always shown on the x-axis. |
| **By Server** | Stacked bar chart of top 8 servers by volume (remainder grouped as `Others(N)`). Per-server breakdown table for the selected hour. |
| **Yesterday vs Today** | Overlaid line charts with a % change comparison table. |
| **HAU & DAU** | Hourly Active Users trend · Daily Active Users trend. Stat cards for peak, average, and total. |
| **Daily Summary** | All days in the DB with totals and per-server breakdown. |
| **Storage Health** | DB size · row counts · RAM usage. Every metric has an ⓘ hover explanation. |

### Features

- **Day selector** — Yesterday / Today / Custom date. Uses local browser time — critical for correct date calculation in the `+0600` timezone.
- **Hour drill-down** — click any hour pill to filter all charts and KPI cards to that single hour.
- **Universal hover tooltips** — every chart (line and bar) shows a floating tooltip. Line charts use a vertical scan-line: move the mouse anywhere across the chart area and the crosshair snaps to the nearest hour, showing all series values simultaneously. Bar charts show per-segment breakdowns and totals on hover. No need to hit a specific dot.
- **Smart tooltip positioning** — tooltip flips left/right and clamps to viewport edges so it never clips off-screen.
- **Auto-refresh** — data reloads every 60 seconds.

---

## Gunicorn Worker Count

The terminal runs **`-w 1`**. Here is why.

### Accuracy requirement

Gunicorn uses a pre-fork model: each worker is an independent OS process with its **own copy of the in-memory MSISDN deduplication sets**. With multiple workers, the same subscriber's requests are distributed across workers by the OS round-robin scheduler. Each worker independently counts that subscriber as "unique" in its own set, and the DB ends up with inflated counts.

| Workers | MSISDN accuracy | Mechanism |
|---|---|---|
| 8 workers (original) | ~+60% over | Each worker sees ~50% of batches; SUM inflates |
| 2 workers | ~+3–5% over | MAX(worker1, worker2) reduces but doesn't eliminate |
| **1 worker** | **exact (matches Kibana)** | Single set = single source of truth |

### Capacity at current traffic (~24 M lines/day, 21 servers)

| Metric | Value |
|---|---|
| Average batches/sec (all servers) | 2.1 req/s |
| Peak batches/sec (3× traffic spike) | 6.3 req/s |
| Estimated handler time per batch | ~13.5 ms |
| Throughput per worker | ~74 req/s |
| **Headroom at peak (6.3 req/s)** | **12× — well within budget** |

### Resource profile

| Resource | With 1 worker |
|---|---|
| CPU at avg load | ~2–3% of one core |
| MSISDN set RAM | ~25 MB |
| **Total server RAM** | **~25 MB** |

Traffic would need to grow **12-fold** before 1 worker becomes a bottleneck. The workload is entirely I/O-bound.

---

## Configuration

### Terminal environment variables

| Variable | Default | Description |
|---|---|---|
| `ANALYTICS_DB` | `/app/log-terminal/analytics.db` | SQLite database path |
| `BASE_LOG_DIR` | `/app/log/access-log-terminal/` | Root directory for stored log files |
| `MSISDN_HOUR_WINDOW` | `26` | Hours of hourly MSISDN sets to keep in RAM |
| `MSISDN_DAY_WINDOW` | `2` | Days of daily MSISDN sets to keep in RAM |
| `CLEANUP_INTERVAL` | `3600` | Seconds between periodic cleanup runs |
| `FILES_SEEN_DAYS` | `7` | Days to retain `files_seen` dedup rows |
| `DB_TIMEOUT` | `30` | SQLite connection timeout in seconds |
| `PORT` | `8000` | Listen port when running without Gunicorn |

### Shipper environment variables

| Variable | Default | Description |
|---|---|---|
| `LOG_DIR` | — | Directory to watch for nginx log files |
| `RECEIVER_URL` | — | `http://10.10.23.212:8000/upload` |
| `SERVER_IP` | — | This server's IP address (sent in every batch) |
| `BATCH_SIZE` | `1000` | Max lines per batch |
| `BATCH_INTERVAL` | `10` | Max seconds between batches |
| `RETRY_DELAY` | `5` | Seconds between retry attempts on failure |
| `MAX_RETRIES` | `3` | Max retries before a batch is discarded |

---

## Deployment

### Terminal setup

```bash
# 1. Copy receiver
scp log-receiver.py user@10.10.23.212:/app/log-terminal/

# 2. Install dependencies
pip3 install flask gunicorn --break-system-packages

# 3. Set environment variables
export ANALYTICS_DB=/app/log-terminal/analytics.db
export BASE_LOG_DIR=/app/log/access-log-terminal/

# 4. Start (1 worker for accurate MSISDN counts)
cd /app/log-terminal
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --access-logfile /app/log/access-log-terminal/gunicorn_access.log \
  --error-logfile  /app/log/access-log-terminal/gunicorn_error.log \
  --pid /app/log-terminal/gunicorn.pid

# 5. Verify
curl http://10.10.23.212:8000/health   # → OK
```

> ⚠️ **`--preload` is required.** It ensures `init_db()` runs exactly once in the master process before workers fork. Any change to `log-receiver.py` — including dashboard changes — requires a **full restart**, not just `kill -HUP`.

### Shipper setup

```bash
# Run on each source server

# 1. Copy shipper
scp log-shipper.py user@10.10.21.44:/app/log-shipper/

# 2. Install dependencies
pip3 install watchdog requests --break-system-packages

# 3. Configure via systemd (recommended)
```

#### systemd service unit

```ini
# /etc/systemd/system/log-shipper.service
[Unit]
Description=MyGP Log Shipper
After=network.target

[Service]
ExecStart=/usr/bin/python3 /app/log-shipper/log-shipper.py
Restart=on-failure
RestartSec=10
Environment=LOG_DIR=/var/log/nginx/
Environment=RECEIVER_URL=http://10.10.23.212:8000/upload
Environment=SERVER_IP=10.10.21.44

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now log-shipper
systemctl status log-shipper
```

---

## Backfilling Historical Data

The receiver only learns about log lines it receives live via POST. If the analytics DB is reset (or a new DB is started mid-day), files already written to disk are not automatically re-indexed. Use `backfill_analytics.py` to populate the DB from the files already on disk.

### How it works

The script walks `BASE_LOG_DIR`, reads every matching log file line-by-line (constant memory regardless of file size), extracts MSISDNs using the same regex as the receiver, and writes line counts + unique MSISDN counts into `hourly_stats` and `daily_stats`. It skips any `(date_hour, server_ip)` pair that already has data, so it is **safe to run alongside the live receiver** and **safe to run multiple times**.

### Resource cost

Based on actual file sizes on the terminal (`~6.6 GB` across 21 servers):

| | |
|---|---|
| Estimated runtime | ~30 seconds |
| Peak RAM usage | ~3 MB |
| Read pattern | sequential, one file at a time |

### Usage

```bash
# Dry run — prints every file that would be processed, writes nothing
python3 backfill_analytics.py --dry-run

# Full backfill of all files on disk
python3 backfill_analytics.py

# Only a specific date
python3 backfill_analytics.py --date 2026-03-11

# Re-process files that already have data (e.g. after a schema change)
python3 backfill_analytics.py --force
```

After the backfill completes, verify the results:

```bash
curl 'http://10.10.23.212:8000/stats?hours=48' | python3 -m json.tool
curl  http://10.10.23.212:8000/stats/storage   | python3 -m json.tool
```

### Fixing dashed server_ip rows (one-time migration)

If the DB contains rows with dashed IPs (e.g. `10-10-21-44` instead of `10.10.21.44`) from an earlier version of the receiver, run the inline fix:

```bash
python3 - << 'EOF'
import sqlite3, re
DB = '/app/log-terminal/analytics.db'
conn = sqlite3.connect(DB, timeout=30)
conn.execute("PRAGMA journal_mode=WAL")
pat = re.compile(r'^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$')
dashed = [r[0] for r in conn.execute("SELECT DISTINCT server_ip FROM hourly_stats") if pat.match(r[0])]
print(f"Dashed IPs found: {len(dashed)}")
# ... (see fix_server_ip.py for full merge logic)
EOF
```

> **This is no longer needed for new deployments.** The receiver now stores dotted IPs natively.

---

## Operations

### Restart terminal (required after any code change)

```bash
kill -TERM $(cat /app/log-terminal/gunicorn.pid)
sleep 3
cp log-receiver.py /app/log-terminal/log-receiver.py
cd /app/log-terminal
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --pid /app/log-terminal/gunicorn.pid
```

### Health checks

```bash
# Worker running?  (expect 2: 1 master + 1 worker)
ps aux | grep gunicorn | grep -v grep | wc -l

# Liveness
curl http://10.10.23.212:8000/health   # → OK

# DB rows and latest hour
python3 -c "
import sqlite3
c = sqlite3.connect('/app/log-terminal/analytics.db')
print('hourly rows :', c.execute('SELECT COUNT(*) FROM hourly_stats').fetchone()[0])
print('latest hour :', c.execute('SELECT MAX(date_hour) FROM hourly_stats').fetchone()[0])
print('servers today:', c.execute(
  \"SELECT COUNT(DISTINCT server_ip) FROM hourly_stats WHERE date_hour LIKE '$(date +%Y-%m-%d)%'\"
).fetchone()[0])
"

# Storage and RAM metrics
curl -s http://10.10.23.212:8000/stats/storage | python3 -m json.tool

# Recent errors
tail -30 /app/log/access-log-terminal/gunicorn_error.log
```

### MSISDN accuracy vs Kibana

Expected accuracy with `-w 1`: **exact match** (within rounding of Kibana's HyperLogLog approximation, typically <0.5%).

If counts diverge after a restart, it is because the in-memory dedup sets reset with the process. The sets rebuild as new batches arrive. Historical hours in the DB are not affected — only the current hour's live count may differ briefly after a restart.

---

*Internal use only — MyGP Platform Engineering*
