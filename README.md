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
| **Gunicorn workers** | 2 |

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
  │  Gunicorn  (2 workers, --preload)                           │
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

`len(set)` at flush time gives the exact unique subscriber count for that period.

### SQLite schema

```sql
-- Primary analytics table: one row per (hour × server)
CREATE TABLE hourly_stats (
  date_hour       TEXT,   -- "YYYY-MM-DD HH"
  server_ip       TEXT,   -- "10-10-21-44"
  line_count      INTEGER DEFAULT 0,
  file_count      INTEGER DEFAULT 0,
  unique_msisdns  INTEGER DEFAULT 0,
  PRIMARY KEY (date_hour, server_ip)
);

-- Rolled-up daily totals
CREATE TABLE daily_stats (
  date            TEXT,
  server_ip       TEXT,
  line_count      INTEGER DEFAULT 0,
  unique_msisdns  INTEGER DEFAULT 0,
  PRIMARY KEY (date, server_ip)
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
- **Hover tooltips** — all line and bar charts show floating value cards on hover.
- **Auto-refresh** — data reloads every 60 seconds.

---

## Gunicorn Worker Count

The terminal runs **`-w 2`**. Here is why.

Gunicorn uses a pre-fork model: each worker is an independent OS process with its own copy of the in-memory MSISDN deduplication sets. With 2 workers, traffic is split roughly 50/50 — meaning the same subscriber's requests are likely to land on the same worker within any given hour, keeping deduplication accurate. More workers fragment the sets further and inflate unique counts without any throughput benefit, because the workload is I/O-bound, not CPU-bound.

### Capacity at current traffic (~24 M lines/day, 21 servers)

| Metric | Value |
|---|---|
| Average batches/sec (all servers) | 2.1 req/s |
| Peak batches/sec (3× traffic spike) | 6.3 req/s |
| Estimated handler time per batch | ~13.5 ms |
| Throughput per worker | ~74 req/s |
| **Total capacity with 2 workers** | **~148 req/s** |
| **Headroom at 3× peak** | **23× — well within budget** |

### Resource profile

| Resource | Per worker (avg) | Per worker (3× peak) |
|---|---|---|
| CPU | ~1–2% of one core | ~4–5% of one core |
| MSISDN set RAM | ~25 MB | ~25 MB |
| **Total server RAM (both workers)** | **~50 MB** | **~50 MB** |

Traffic would need to grow **23-fold** before 2 workers becomes a bottleneck.

---

## Configuration

### Terminal environment variables

| Variable | Default | Description |
|---|---|---|
| `ANALYTICS_DB` | `/app/log-shipper/analytics.db` | SQLite database path |
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
export ANALYTICS_DB=/app/log-shipper/analytics.db
export BASE_LOG_DIR=/app/log/access-log-terminal/

# 4. Start
cd /app/log-terminal
gunicorn --preload -w 2 -b 0.0.0.0:8000 log-receiver:app \
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

---

## Operations

### Restart terminal (required after any code change)

```bash
kill -TERM $(cat /app/log-terminal/gunicorn.pid)
sleep 3
cp log-receiver.py /app/log-terminal/log-receiver.py
cd /app/log-terminal
gunicorn --preload -w 2 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --access-logfile /app/log/access-log-terminal/gunicorn_access.log \
  --error-logfile  /app/log/access-log-terminal/gunicorn_error.log \
  --pid /app/log-terminal/gunicorn.pid
```

### Graceful reload (Python function logic only, no HTML changes)

```bash
cp log-receiver.py /app/log-terminal/log-receiver.py
kill -HUP $(cat /app/log-terminal/gunicorn.pid)
```

### Health checks

```bash
# Workers running?  (expect 3: 1 master + 2 workers)
ps aux | grep gunicorn | grep -v grep | wc -l

# Liveness
curl http://10.10.23.212:8000/health   # → OK

# DB rows and latest hour
python3 -c "
import sqlite3
c = sqlite3.connect('/app/log-shipper/analytics.db')
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

---

*Internal use only — MyGP Platform Engineering*