# MyGP Log Shipping & Analytics System

Real-time nginx log collection, centralisation, and analytics across 21 application servers — no message broker, no cloud dependency, two Python files.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [System Components](#system-components)
- [Prerequisites](#prerequisites)
- [Installation & Deployment](#installation--deployment)
  - [Terminal (Receiver) Setup](#terminal-receiver-setup)
  - [Shipper Setup (Each Source Server)](#shipper-setup-each-source-server)
- [Environment Variables](#environment-variables)
- [File Storage Layout](#file-storage-layout)
- [SQLite Database Schema](#sqlite-database-schema)
- [Dashboard — 9 Analytics Tabs](#dashboard--9-analytics-tabs)
- [API Endpoints (Quick Reference)](#api-endpoints-quick-reference)
- [Gunicorn Worker Count — Why Exactly 1](#gunicorn-worker-count--why-exactly-1)
- [Operations Runbook](#operations-runbook)
- [Monitoring Checklist](#monitoring-checklist)
- [Failure Modes & Recovery](#failure-modes--recovery)
- [Resource Profile & Capacity](#resource-profile--capacity)
- [Backfilling Historical Data](#backfilling-historical-data)
- [Known Constraints](#known-constraints)

---

## Overview

The MyGP log pipeline ships nginx access logs from **21 source servers** (`10.10.21.x`) to a central **terminal** (`10.10.23.212:8000`) in real time.

On arrival, each log line is:
1. Written to disk in 20-minute time-window files (preserving the raw access log permanently)
2. Parsed for TPS (Transactions Per Second) tracking per API endpoint, per second
3. Parsed for MSISDN (subscriber ID) extraction and deduplicated in RAM
4. Aggregated into SQLite for persistent analytics

Results are exposed through a live web dashboard at `http://10.10.23.212:8000/dashboard` (auto-refresh every 60 seconds) and a JSON API.

| What | Value |
|---|---|
| Source servers | 21 × application servers (`10.10.21.x`) |
| Terminal | `10.10.23.212:8000` |
| Stack | Python 3.6+ · Flask · Gunicorn · SQLite (WAL) |
| Log format | nginx access log with embedded `\x22`-encoded JSON fields |
| Dashboard | `http://10.10.23.212:8000/dashboard` |
| Gunicorn workers | **1** (critical — see [Gunicorn Worker Count](#gunicorn-worker-count--why-exactly-1)) |
| DB growth | ~14 MB/year, projected maximum ~70 MB |

---

## Architecture

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  SOURCE SERVERS  (×21,  10.10.21.x)                                 │
  │                                                                     │
  │  nginx ──writes──► access.log                                       │
  │                        │                                            │
  │  log-shipper.py ◄─tails┘                                           │
  │       │  pending_fragment buffer  (handles split lines)             │
  │       │  batch accumulates  (≤1000 lines  or  ≤30 s)               │
  │       │  gzip compress + POST                                       │
  │       ▼                                                             │
  │  POST /upload  ─────────────────────────────────────────────────►  │
  └────────────────────────────────────────────────────────────────┬────┘
                                                                   │
                            gzip JSON  { log, host, meta }         │
                                                                   ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  TERMINAL  (10.10.23.212:8000)  —  log-receiver.py                       │
│                                                                          │
│  Gunicorn  (--preload  -w 1)                                             │
│       │                                                                  │
│       ├─① _merge_continuations()   rejoin split nginx lines             │
│       ├─② bucket by timestamp      → 20-min file windows                │
│       ├─③ write to disk            BASE_LOG_DIR/{hostname}/*.log        │
│       └─④ _record_analytics()                                           │
│             ├─ TPS accumulation    _tps_window[url][second]++           │
│             ├─ Global TPS          _global_sec_map[second]++            │
│             ├─ MSISDN dedup        in-memory sets, delta→ SQLite        │
│             ├─ Server heartbeat    _server_last_seen[ip] = now          │
│             └─ SQLite upserts      hourly/daily/url_stats               │
│                                                                          │
│  Background thread (every 3600s)                                         │
│       ├─ Evict stale MSISDN sets (>26h / >2d)                           │
│       ├─ Evict stale TPS window (>2h) and global map (>26h)             │
│       ├─ DELETE files_seen rows > 7 days + VACUUM SQLite                │
│       └─ Checkpoint MSISDN sets to msisdn_state.pkl                     │
│                                                                          │
│  API endpoints: /upload /stats /stats/tps /stats/tps/agg                │
│                 /stats/tps/global /stats/heartbeat /stats/storage        │
│                 /dashboard /admin/checkpoint /health                     │
│                                                                          │
│  Browser ◄──── GET /dashboard  (inline SPA, SVG charts, 60s refresh)    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## System Components

### Log Shipper (`log-shipper.py`)

Runs as a daemon (systemd service) on every source server. Tails the nginx access log and POSTs batches to the terminal.

**How it works:**

1. **File discovery** — Uses `watchdog` (Linux inotify) to detect new/modified `.log` files in `LOG_DIR`.

2. **Pending fragment buffer** — nginx embeds a JSON blob per request; if a User-Agent or URL contains a literal newline, nginx splits one logical entry across two physical lines. The shipper holds any incomplete line in `_pending_fragment` and prepends it to the next `readline()`, ensuring only complete records enter the batch queue.

3. **Batching** — Lines accumulate until:
   - `BATCH_SIZE` lines are buffered (default: 1000), or
   - `BATCH_INTERVAL` seconds have elapsed (default: 30 s)

4. **HTTP delivery** — Posts gzip-compressed JSON:
   ```json
   {
     "log":  "raw log lines joined by \n",
     "host": "server-hostname",
     "meta": {"lines": 340, "start_offset": 12345678, "end_offset": 12349012}
   }
   ```
   Failed POSTs retry up to `MAX_RETRIES` times. After all retries are exhausted, the batch is discarded to prevent unbounded memory growth.

### Log Terminal (`log-receiver.py`)

3,100-line single-file Flask application. All in-memory state, all analytics, all SQLite writes, all dashboard HTML live in this one file.

**Ingest pipeline (per batch):**
```
POST /upload
  ├─ 1. Decompress gzip (if Content-Encoding: gzip) or parse plain JSON
  ├─ 2. _merge_continuations()   → reassemble split nginx lines
  ├─ 3. Per-line timestamp parse → 20-minute window file bucket
  ├─ 4. Append lines to disk     → BASE_LOG_DIR/{hostname}/{window}.log
  └─ 5. _record_analytics()      → TPS, MSISDN, heartbeat, SQLite
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.6+ (3.8+ recommended) |
| Flask | 2.x+ |
| gunicorn | 20.x+ |
| SQLite | 3.8.3+ (WAL mode required) |
| watchdog | 2.x (shipper only) |
| requests | 2.x (shipper only) |

```bash
# Terminal
pip3 install flask gunicorn

# Shipper (each source server)
pip3 install watchdog requests
```

**Runtime resources (terminal):**

| Resource | Typical value |
|---|---|
| RAM | 200–400 MB (MSISDN sets dominate) |
| CPU | < 5% of one core at normal load |
| Disk | ~1–3 GB/day depending on traffic (raw log files are never auto-deleted) |

---

## Installation & Deployment

### Terminal (Receiver) Setup

```bash
# 1. Copy receiver to terminal server
scp log-receiver.py user@10.10.23.212:/app/log-terminal/

# 2. Install dependencies
pip3 install flask gunicorn --break-system-packages

# 3. Create required directories
mkdir -p /app/log/access-log-terminal
mkdir -p /app/log-terminal

# 4. Start with Gunicorn (--preload and -w 1 are critical, see below)
cd /app/log-terminal
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --pid     /app/log-terminal/gunicorn.pid \
  --access-logfile /app/log/access-log-terminal/gunicorn_access.log \
  --error-logfile  /app/log/access-log-terminal/gunicorn_error.log

# 5. Verify
curl http://10.10.23.212:8000/health       # → OK
curl http://10.10.23.212:8000/stats/storage | python3 -m json.tool
```

**Why `--preload` is required:** `init_db()` runs exactly once in the master process before workers fork. Without `--preload`, each worker independently calls `init_db()`, causing a race on `PRAGMA journal_mode=WAL` (which needs an exclusive lock). The first worker to win gets the lock; all others log a warning and continue normally — the warning is safe to ignore, but `--preload` eliminates it entirely.

**After any code change**, a full restart is required because `--preload` bakes the app code into the master process:
```bash
kill -TERM $(cat /app/log-terminal/gunicorn.pid)
sleep 3
cp /path/to/new/log-receiver.py /app/log-terminal/
cd /app/log-terminal
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon --pid /app/log-terminal/gunicorn.pid
```

### Shipper Setup (Each Source Server)

```bash
# 1. Copy shipper
scp log-shipper.py user@10.10.21.44:/app/log-shipper/

# 2. Install dependencies
pip3 install watchdog requests --break-system-packages

# 3. Create systemd service
```

**systemd service unit** (`/etc/systemd/system/log-shipper.service`):
```ini
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

## Environment Variables

### Terminal

| Variable | Default | Description |
|---|---|---|
| `BASE_LOG_DIR` | `/app/log/access-log-terminal/` | Root directory for stored log files |
| `ANALYTICS_DB` | `/app/log-terminal/analytics.db` | SQLite database path |
| `STATE_PATH` | `/app/log-terminal/msisdn_state.pkl` | MSISDN dedup state checkpoint |
| `MSISDN_HOUR_WINDOW` | `26` | Hours to retain hourly MSISDN dedup sets in RAM |
| `MSISDN_DAY_WINDOW` | `2` | Days to retain daily MSISDN dedup sets in RAM |
| `CLEANUP_INTERVAL` | `3600` | Seconds between background cleanup runs |
| `FILES_SEEN_DAYS` | `7` | Days to retain `files_seen` rows in SQLite |
| `DB_TIMEOUT` | `30` | SQLite lock wait timeout (seconds) |
| `URL_STATS_MAX_URLS` | `500` | Max distinct URL paths tracked in `_tps_window` RAM map |
| `MAX_CONTENT_LENGTH_MB` | _(unset)_ | Optional upload size cap (MB). Unset = no limit |
| `PORT` | `8000` | Dev mode port (`python log-receiver.py` only) |

### Shipper

| Variable | Default | Description |
|---|---|---|
| `LOG_DIR` | — | Directory to watch for nginx log files |
| `RECEIVER_URL` | — | `http://10.10.23.212:8000/upload` |
| `SERVER_IP` | — | This server's IP (sent in every batch as `host` field) |
| `BATCH_SIZE` | `1000` | Max lines per batch |
| `BATCH_INTERVAL` | `30` | Max seconds between batches |
| `RETRY_DELAY` | `5` | Seconds between retry attempts |
| `MAX_RETRIES` | `3` | Retries before discarding a batch |

---

## File Storage Layout

```
/app/log/access-log-terminal/          ← BASE_LOG_DIR
├── stats.log                          ← application log (info/error/warn)
├── gunicorn_access.log
├── gunicorn_error.log
├── server-hostname-1/                 ← one dir per hostname sent by shipper
│   ├── MyGP_accessLog_2501261400_00-19_10-10-21-44.log
│   ├── MyGP_accessLog_2501261400_20-39_10-10-21-44.log
│   ├── MyGP_accessLog_2501261400_40-59_10-10-21-44.log
│   └── MyGP_accessLog_2501261401_00-19_10-10-21-44.log   ← next hour
├── server-hostname-2/
│   └── ...

/app/log-terminal/
├── analytics.db                       ← SQLite analytics (WAL mode)
├── analytics.db-wal                   ← WAL journal (normal; not an error)
├── analytics.db-shm                   ← shared memory (normal)
├── msisdn_state.pkl                   ← MSISDN dedup state checkpoint
├── msisdn_state.pkl.tmp               ← atomic write temp (briefly present)
└── gunicorn.pid                       ← Gunicorn master PID
```

**File naming:** `MyGP_accessLog_{YYMMDDHH}_{window}_{source_ip_dashed}.log`

| Part | Example | Meaning |
|---|---|---|
| `YYMMDDHH` | `2501261400` | Year 2025, Jan 26, hour 14 (UTC) |
| `window` | `20-39` | Minutes 20–39 of that hour |
| `source_ip_dashed` | `10-10-21-44` | Source IP with dashes (for filesystem safety) |

Files are **append-only** — never truncated. A restart reopens the same file and continues appending. No data loss on restart.

> Directory names use dots (`10.10.21.44/`), filenames use dashes (`..._10-10-21-44.log`). SQLite always stores IPs with dots.

---

## SQLite Database Schema

Database: `analytics.db` — **WAL mode**, `synchronous=NORMAL`

```sql
-- Aggregated line counts per server per hour
CREATE TABLE hourly_stats (
    date_hour      TEXT NOT NULL,   -- '2025-01-26 14'
    server_ip      TEXT NOT NULL,   -- '10.10.21.44'  (dotted, never dashed)
    line_count     INTEGER DEFAULT 0,
    file_count     INTEGER DEFAULT 0,
    unique_msisdns INTEGER DEFAULT 0,
    PRIMARY KEY (date_hour, server_ip)
);
CREATE INDEX idx_hourly_date ON hourly_stats(date_hour);

-- Daily aggregates per server
CREATE TABLE daily_stats (
    date           TEXT NOT NULL,   -- '2025-01-26'
    server_ip      TEXT NOT NULL,
    line_count     INTEGER DEFAULT 0,
    unique_msisdns INTEGER DEFAULT 0,
    PRIMARY KEY (date, server_ip)
);
CREATE INDEX idx_daily_date ON daily_stats(date);

-- Per-endpoint TPS and performance metrics, keyed by hour
CREATE TABLE url_stats (
    date_hour        TEXT NOT NULL,   -- '2025-01-26 14'
    url_path         TEXT NOT NULL,   -- '/mygpapi/v2/balance'
    max_tps          INTEGER DEFAULT 0,
    total_reqs       INTEGER DEFAULT 0,
    sum_resp_ms      INTEGER DEFAULT 0,
    api_error_count  INTEGER DEFAULT 0,
    PRIMARY KEY (date_hour, url_path)
);
CREATE INDEX idx_url_stats_hour ON url_stats (date_hour, max_tps DESC);

-- File deduplication registry (auto-purged after FILES_SEEN_DAYS days)
CREATE TABLE files_seen (
    date_hour TEXT NOT NULL,
    server_ip TEXT NOT NULL,
    filename  TEXT NOT NULL,
    PRIMARY KEY (date_hour, server_ip, filename)
);

-- Internal key-value metadata store
CREATE TABLE db_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
    -- Active key: 'last_cleanup' → ISO8601 timestamp of last cleanup run
);
```

**Upsert strategy:** All writes use `INSERT OR IGNORE` + `UPDATE` (not `ON CONFLICT DO UPDATE`) for SQLite 3.8 compatibility.

**DB growth:**

| Table | ~Daily growth | 1 year | 5 years |
|---|---|---|---|
| `hourly_stats` | ~35 KB | ~13 MB | ~65 MB |
| `daily_stats` | ~1.5 KB | <1 MB | <3 MB |
| `url_stats` | ~50 KB | ~18 MB | ~90 MB |
| `files_seen` | capped at 7 days | ~5 MB | ~5 MB |
| **Total** | | **~37 MB** | **~165 MB** |

---

## Dashboard — 9 Analytics Tabs

Open at `http://10.10.23.212:8000/dashboard` — auto-refreshes every **60 seconds**.

Zero external CDN dependencies. The entire dashboard is served as inline HTML/JS/CSS (~70 KB uncompressed) — works fully air-gapped.

| Tab | ID | Primary API | What you see |
|---|---|---|---|
| **Overview** | `overview` | `/stats` | Log lines/hr · unique MSISDNs/hr · active servers/hr · files/hr — always 24 hours on x-axis |
| **By Server** | `byserver` | `/stats` | Per-server breakdown table: lines/hour, per-day totals, unique MSISDN counts |
| **TPS & Endpoints** | `tps` | `/stats/tps/agg` | Paginated table (20/page) of all API endpoints sorted by peak TPS. Click any row → hourly trend chart for that endpoint |
| **Global Peak TPS** | `globalpeak` | `/stats/tps/global` | Combined TPS across all endpoints. Peak second identification, top-10 busiest seconds table, per-minute sparkline chart |
| **Yesterday vs Today** | `compare` | `/stats` | Side-by-side line chart — today's traffic vs yesterday. % delta summary |
| **HAU & DAU** | `haudau` | `/stats` | Hourly Active Users (HAU) trend · Daily Active Users (DAU) over 7 days. Peak/avg/total stat cards |
| **Daily Summary** | `daily` | `/stats` | 7-day rolling table: total lines, active servers, unique users per day |
| **Storage Health** | `storage` | `/stats/storage` | SQLite size/row counts · RAM usage for MSISDN sets · last cleanup time |

**Universal controls:**
- **Day selector** — Yesterday / Today / Custom date (uses browser local time for correct `+0600` day boundary)
- **Hour drill-down** — click any chart point/bar to filter all tabs to that UTC hour
- **Search box** (TPS tab) — filters endpoint table by URL substring, resets to page 1

---

## API Endpoints (Quick Reference)

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/upload` | None | Receive a log batch from a shipper |
| `GET` | `/stats` | None | Hourly + daily aggregates from SQLite |
| `GET` | `/stats/tps` | None | Per-URL hourly TPS rows (raw, multi-row) |
| `GET` | `/stats/tps/agg` | None | Fast single-row-per-URL aggregation |
| `GET` | `/stats/tps/global` | None | Combined all-endpoint per-second TPS |
| `GET` | `/stats/heartbeat` | None | Seconds-since-last-batch per server |
| `GET` | `/stats/storage` | None | DB size, row counts, RAM usage |
| `GET` | `/dashboard` | None | Serves the analytics SPA |
| `POST` | `/admin/checkpoint` | None | Force-save MSISDN state to disk |
| `GET` | `/health` | None | Liveness probe — returns `200 OK` |

Full documentation with curl examples, parameters, response schemas, error codes, and monitoring notes is in [DOCUMENTATION.md](./DOCUMENTATION.md).

---

## Gunicorn Worker Count — Why Exactly 1

**The rule: always run `-w 1`. Never increase to 2+.**

Gunicorn uses a pre-fork model. Each worker is an independent OS process with its own copy of all in-memory state. With `-w 2`:

- Batches from the 21 servers are distributed round-robin across workers
- Each worker maintains its own `_msisdn_hour` / `_msisdn_day` Python sets
- A subscriber who uses the app across two different batch windows may be seen by Worker A in one batch and Worker B in the next. Each counts that subscriber as "unique" in its own private set
- The SQLite `unique_msisdns` column ends up with inflated counts from both workers

| Workers | MSISDN accuracy | Why |
|---|---|---|
| 8 workers (pre-fix) | ~+60% over | Each sees ~12.5% of batches; each inflates independently |
| 2 workers | ~+3–5% over | Each sees ~50% of batches |
| **1 worker** | **exact** | One set = one source of truth — matches Kibana |

**Capacity headroom with 1 worker:**

| Metric | Value |
|---|---|
| Average batches/sec (21 servers) | ~2.1 req/s |
| Peak batches/sec (3× spike) | ~6.3 req/s |
| Estimated handler time per batch | ~13–15 ms |
| Throughput per worker | ~70+ req/s |
| **Headroom at peak** | **~10×** |

Traffic would need to grow 10-fold before 1 worker becomes a bottleneck. The workload is almost entirely I/O-bound (disk append + SQLite write).

---

## Operations Runbook

### Restart (required after any code change)

```bash
# Graceful stop (saves MSISDN state before exit via SIGTERM handler)
kill -TERM $(cat /app/log-terminal/gunicorn.pid)
sleep 3

# Deploy new code
cp /path/to/new/log-receiver.py /app/log-terminal/

# Start
cd /app/log-terminal
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --pid     /app/log-terminal/gunicorn.pid \
  --access-logfile /app/log/access-log-terminal/gunicorn_access.log \
  --error-logfile  /app/log/access-log-terminal/gunicorn_error.log

# Verify
curl http://10.10.23.212:8000/health
```

### Force checkpoint (without restart)

```bash
curl -X POST http://10.10.23.212:8000/admin/checkpoint
```

Atomically saves the current MSISDN sets to `msisdn_state.pkl`. Safe to call at any time — does not interrupt in-flight requests.

### Config-only reload (no code changes)

```bash
kill -HUP $(cat /app/log-terminal/gunicorn.pid)
```

Triggers `_save_state()` before the worker restarts. MSISDN continuity is preserved.

### Check process health

```bash
# Expect 2 lines: 1 master + 1 worker
ps aux | grep gunicorn | grep -v grep | wc -l

# Liveness
curl http://10.10.23.212:8000/health   # → OK

# All 21 servers reporting?
curl -s http://10.10.23.212:8000/stats/heartbeat | python3 -m json.tool
# Check no server shows > 120 seconds

# DB health
curl -s http://10.10.23.212:8000/stats/storage | python3 -m json.tool

# Recent errors
tail -50 /app/log/access-log-terminal/stats.log | grep ERROR
```

---

## Monitoring Checklist

| Signal | Check | Healthy threshold |
|---|---|---|
| App alive | `GET /health` | `200 OK` |
| All shippers active | `GET /stats/heartbeat` | Every known IP `< 120` seconds |
| DB size | `GET /stats/storage` → `db.size_mb` | `< 200` MB |
| Last cleanup | `GET /stats/storage` → `db.last_cleanup` | Within last 2 hours |
| RAM usage | `GET /stats/storage` → `ram.estimated_ram_mb` | `< 500` MB |
| Error log | `tail stats.log \| grep ERROR` | Zero `[ERROR]` lines |
| TPS sanity | `GET /stats/tps/global` → `peak_tps` | In expected range for time of day |
| Worker count | `ps aux \| grep gunicorn` | Exactly 2 lines (master + 1 worker) |

---

## Failure Modes & Recovery

### Shipper stops sending from one server

**Symptom:** `/stats/heartbeat` shows one IP with `> 300` seconds
**Cause:** shipper process crashed, nginx log rotation moved the file, disk full on source server
**Recovery:**
```bash
# On the affected source server:
systemctl status log-shipper
journalctl -u log-shipper -n 50
systemctl restart log-shipper

# Verify recovery:
curl -s http://10.10.23.212:8000/stats/heartbeat | python3 -m json.tool
```
**Data loss:** Lines accumulated during the outage are re-read when the shipper restarts (watchdog-based inotify re-discovers the file). No data is permanently lost unless the source log file was rotated and deleted before the shipper restarted.

---

### Terminal process dies unexpectedly (OOM kill, power cycle)

**Symptom:** `/health` returns connection refused; gunicorn.pid is stale
**Recovery:**
```bash
rm -f /app/log-terminal/gunicorn.pid
cd /app/log-terminal
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon --pid /app/log-terminal/gunicorn.pid
```
**Data integrity:**
- Raw log files on disk: **no loss** (files are append-only)
- SQLite DB: **no loss** — WAL mode guarantees the DB is consistent at process exit even without `fsync`. The WAL file is replayed on next open
- MSISDN in-memory state: **may roll back up to `CLEANUP_INTERVAL` seconds** (3600 s default) if the last periodic checkpoint was recent. The `/admin/checkpoint` endpoint and SIGTERM handler both call `_save_state()`. If the process was killed with SIGKILL (not SIGTERM), the last periodic save is the recovery point

---

### SQLite "database is locked" errors

**Symptom:** `[ERROR]` lines in `stats.log` containing `database is locked`
**Cause:** Either a manual `sqlite3` CLI is holding a lock, or `_cleanup_db()` + analytics write are racing (very rare with WAL mode)
**Recovery:**
```bash
# Check for open SQLite connections outside the app:
fuser /app/log-terminal/analytics.db

# If a manual sqlite3 session is open, close it
# WAL mode allows concurrent reads + one writer, so this is rarely a real issue

# If persistent: checkpoint WAL manually
sqlite3 /app/log-terminal/analytics.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

---

### MSISDN counts differ significantly from Kibana (> 5%)

**Expected deviation:** ~0.5–2% (Kibana uses HyperLogLog approximation; our system uses exact Python `set`)
**If >5% higher than Kibana:**
- Most common cause: recent process restart cleared the in-memory dedup sets. The sets rebuild as new batches arrive — wait 20–30 minutes for the rolling window to refill
- Check if gunicorn is accidentally running 2+ workers: `ps aux | grep gunicorn | grep -v master`

**If >5% lower than Kibana:**
- Check if some shippers are not reporting: `curl http://10.10.23.212:8000/stats/heartbeat`
- Check if any source server's nginx is writing logs to a different path than the shipper watches

---

### Disk full on terminal server

**Symptom:** `/upload` returns `500` or `Write error` appears in `stats.log`
**Cause:** Log files are never auto-deleted; raw log volume accumulates indefinitely
**Recovery:**
```bash
# Check disk usage by server directory:
du -sh /app/log/access-log-terminal/*/

# Delete log files older than N days:
find /app/log/access-log-terminal -name "*.log" -mtime +30 -delete

# Verify app is writing again:
tail -f /app/log/access-log-terminal/stats.log
```
**Note:** Deleting raw log files does not affect the SQLite analytics — the DB is already populated from those files. Only future re-analysis or backfilling would be affected.

---

### SQLite database corrupted

**Symptom:** `sqlite3.DatabaseError: database disk image is malformed`
**Cause:** Power cut during write without WAL (should not happen with WAL mode) or filesystem corruption
**Recovery:**
```bash
# Attempt repair
sqlite3 /app/log-terminal/analytics.db ".recover" | sqlite3 /app/log-terminal/analytics_recovered.db
mv analytics.db analytics.db.corrupt
mv analytics_recovered.db analytics.db

# If recovery fails: backfill from raw logs
python3 backfill_analytics.py
```

---

### State file corrupt (`msisdn_state.pkl`)

**Symptom:** `[ERROR] State load failed` in stats.log on startup
**Cause:** Disk full during atomic write, filesystem corruption
**Recovery:**
```bash
# Safe to delete — the system starts fresh with empty MSISDN sets
rm /app/log-terminal/msisdn_state.pkl
# Restart gunicorn
# MSISDN dedup sets will rebuild over the next 26 hours
# Historical SQLite counts are unaffected
```

---

### `_tps_window` RAM growing unboundedly

**Symptom:** `GET /stats/storage` shows `estimated_ram_mb` increasing over time
**Cause:** `URL_STATS_MAX_URLS` hit, or `_evict_old_url_state()` not running
**Recovery:**
```bash
# Check current URL count
curl -s http://10.10.23.212:8000/stats/tps/agg | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['tps_agg']), 'endpoints tracked')"

# If near or above URL_STATS_MAX_URLS, new endpoints are silently dropped
# Increase the limit if you need more:
export URL_STATS_MAX_URLS=1000
# restart gunicorn
```

---

## Resource Profile & Capacity

### RAM breakdown

| Component | Estimate |
|---|---|
| MSISDN sets (26h window × 21 servers × ~1M daily users) | ~100–300 MB |
| `_tps_window` (2h × 500 URLs × avg 200 seconds) | ~10 MB |
| `_global_sec_map` (26h = ~93,600 seconds) | ~5 MB |
| Flask/Python runtime overhead | ~50 MB |
| **Total** | **~165–365 MB** |

### Throughput per worker

| Metric | Value |
|---|---|
| Average batches/day (21 servers) | ~180,000 |
| Peak batches/sec (3× spike) | ~6.3 req/s |
| Sync disk+DB write per batch | ~5–15 ms |
| Available headroom | ~10× before saturation |

### DB file growth

At current traffic (~25 M lines/day across 21 servers):
- `url_stats` is the fastest-growing table (~500 distinct endpoints × 24 hours/day)
- Total DB size stays under 200 MB for the foreseeable future

---

## Backfilling Historical Data

If the analytics DB is reset or a new DB is started mid-day, use `backfill_analytics.py` to re-populate from files already on disk.

```bash
# Dry run — prints what would be processed, writes nothing
python3 backfill_analytics.py --dry-run

# Full backfill
python3 backfill_analytics.py

# Only a specific date
python3 backfill_analytics.py --date 2026-03-11

# Force re-process even if data already exists
python3 backfill_analytics.py --force
```

The backfill script is **safe to run alongside the live receiver** (uses the same upsert-safe SQL patterns). It skips any `(date_hour, server_ip)` pair that already has data by default. Peak RAM usage: ~3 MB.

After backfill, verify:
```bash
curl -s 'http://10.10.23.212:8000/stats?hours=48' | python3 -m json.tool
curl -s  http://10.10.23.212:8000/stats/storage   | python3 -m json.tool
```

---

## Known Constraints

| Constraint | Value | Implication |
|---|---|---|
| Gunicorn workers | **Must be 1** | In-memory MSISDN dedup is not shared across processes |
| Max tracked URL paths | 500 (configurable) | URLs beyond the limit are tracked in SQLite but not in `_tps_window` RAM |
| TPS accuracy | ±2–4% | ~8% of lines are plain-format nginx (HTTP 499) without `request_start_time`; these use the nginx log timestamp as fallback |
| Global TPS history in RAM | 26 hours | `_global_sec_map` evicted after 26h; older seconds not visible in the Global Peak chart |
| MSISDN window on restart | Up to 3600 s gap | If killed with SIGKILL (not SIGTERM), the last periodic checkpoint is the recovery point |
| Raw log retention | **Never auto-deleted** | Disk must be monitored and old files cleaned manually |
| nginx `\x22` encoding | Handled explicitly | JSON fields in nginx logs use `\x22` (literal backslash-x22) for double quotes, not actual `"`. All regex patterns account for this |

---

*Internal use only — MyGP Platform Engineering*
