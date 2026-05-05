# RT-Log-Sync2 Operations Guide

This document explains how the current codebase works and how to deploy, run, test, and monitor it.
It is written from the existing Python files in this repository.

## 1) What This System Does

RT-Log-Sync2 collects nginx access logs from many source servers and sends them to one central receiver.

At the receiver side, the system:
- stores raw logs in time-windowed files
- updates hourly and daily analytics in SQLite
- keeps in-memory MSISDN dedup state (MSISDN values are never written to SQLite)
- tracks source server heartbeat
- sends email alerts and hourly analytics reports
- serves a live dashboard

Main flow:
1. sender reads new lines from local nginx access log
2. sender batches lines and posts to receiver `/upload`
3. receiver writes lines to host-specific files
4. receiver updates SQLite counters and heartbeat
5. alerting module sends event alerts and hourly report emails

## 2) Repository Files and Purpose

- `log-shipper.py`
  - sender for standard nginx text access log
  - supports rotation, truncation, offset persistence, and retry

- `log_sender-auth_lb.py`
  - sender for auth LB JSON log format
  - converts JSON records to standard nginx-style lines before sending

- `log-receiver.py`
  - Flask app with all ingest, analytics, heartbeat, admin APIs, and dashboard

- `alerting.py`
  - SMTP email sender for instant alerts and hourly report email

- `backfill_analytics.py`
  - one-time backfill utility to populate SQLite from existing stored log files

- `restart-log-terminal.sh`
  - operational restart script for receiver with environment setup and checks

## 3) Architecture

Source servers:
- run one of the sender scripts
- read local access log continuously
- send batches to central receiver

Central receiver:
- Flask + Gunicorn process
- endpoint: `POST /upload`
- writes log files under host directory
- updates SQLite analytics DB
- exposes stats/admin APIs
- exposes dashboard HTML

Storage:
- raw files under `BASE_LOG_DIR`
- analytics DB at `ANALYTICS_DB`
- MSISDN state checkpoint at `STATE_PATH`

## 4) Sender Setup (Standard Sender)

File: `log-shipper.py`

### Dependencies

```bash
pip3 install requests watchdog tenacity
```

### Environment Variables

- `LOG_FILE` default: `/app/log/nginx/access.log`
- `OFFSET_FILE` default: `/app/log-shipper/latest.offset`
- `CHUNK_SIZE` default: `10000`
- `MAX_BATCH_BYTES` default: `5242880`
- `SEND_URL` default: `http://10.10.23.212:8000/upload`
- `LOGGING_FILE` default: `/app/log-shipper/log_shipper_status.log`
- `POLL_INTERVAL` default: `0.5`
- `REQUEST_TIMEOUT_SECS` default: `15`
- `USE_GZIP` default: `1`
- `SENDER_ID` optional override for sender identity

### Behavior

- stores current byte offset in `OFFSET_FILE`
- retries failed sends with tenacity
- computes SHA-256 fingerprint per batch for receiver dedup
- supports log rotation and truncation
- carries pending continuation fragments across restarts

### Run

```bash
python3 log-shipper.py
```

## 5) Sender Setup (Auth LB Sender)

File: `log_sender-auth_lb.py`

### Differences from standard sender

- input log line is JSON object per physical line
- uses `json_to_log_format()` to build standard line format
- filters internal auth probe lines
- no continuation merge needed

### Environment Variables

- `LOG_FILE` default: `/data/nginx/log/access.log`
- `OFFSET_FILE` default: `/data/nginx/log-shipper-2/latest.offset`
- `CHUNK_SIZE` default: `10000`
- `MAX_BATCH_BYTES` default: `5242880`
- `SEND_URL` default: `http://10.10.23.212:8000/upload`
- `LOGGING_FILE` default: `/data/nginx/log-shipper-2/log_shipper_status.log`
- `POLL_INTERVAL` default: `0.5`
- `REQUEST_TIMEOUT_SECS` default: `15`
- `USE_GZIP` default: `1`
- `SENDER_ID` optional

### Run

```bash
python3 log_sender-auth_lb.py
```

## 6) Receiver Setup

File: `log-receiver.py`

### Dependencies

```bash
pip3 install flask gunicorn
```

### Required Paths

- `BASE_LOG_DIR` default: `/app/log/access-log-terminal/`
- `ANALYTICS_DB` default: `/app/log-terminal/analytics.db`
- `STATE_PATH` default: `/app/log-terminal/msisdn_state.pkl`

### Receiver Environment Variables

- `MSISDN_HOUR_WINDOW` default: `26`
- `MSISDN_DAY_WINDOW` default: `2`
- `CLEANUP_INTERVAL` default: `3600`
- `FILES_SEEN_DAYS` default: `7`
- `HOURLY_RETAIN_DAYS` default: `14`
- `DAILY_RETAIN_DAYS` default: `90`
- `BATCH_RETAIN_HOURS` default: `72`
- `SERVER_SILENT_SECS` default: `300`
- `VACUUM_INTERVAL_HOURS` default: `168`
- `KNOWN_SERVERS` optional CSV
- `DB_TIMEOUT` default: `30`
- `MAX_CONTENT_LENGTH_MB` optional
- `PORT` default: `8000`

### Run with Gunicorn

Use single worker for exact in-memory dedup behavior.

```bash
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --pid /app/log-terminal/gunicorn.pid
```

## 7) Alerting Setup

File: `alerting.py`

### Environment Variables

- `ALERT_EMAIL_ENABLED` default: `0`
- `SMTP_HOST` default: `localhost`
- `SMTP_PORT` default: `587`
- `SMTP_USER` default: empty
- `SMTP_PASSWORD` default: empty
- `SMTP_USE_TLS` default: `1`
- `SMTP_USE_SSL` default: `0`
- `ALERT_FROM` default: `logreceiver@localhost`
- `ALERT_TO` default: empty CSV
- `ALERT_SUPPRESS_SECS` default: `1800`
- `HOURLY_REPORT_ENABLED` default: `1`
- `REPORT_TZ_OFFSET_MINUTES` default: `360`
- `REPORT_TZ_LABEL` default: generated from offset

### Alert Types

Instant alerts:
- server became silent
- server recovered
- receiver write failure
- analytics DB repeated failure

Scheduled report:
- hourly summary email
- includes previous-day same-hour comparison
- includes active/inactive server view

## 8) Data Model (SQLite)

Receiver creates and updates these tables:

- `hourly_stats`
  - `date_hour`, `server_ip`, `line_count`, `file_count`, `unique_msisdns`
  - primary key: `(date_hour, server_ip)`

- `daily_stats`
  - `date`, `server_ip`, `line_count`, `unique_msisdns`
  - primary key: `(date, server_ip)`

- `files_seen`
  - `date_hour`, `server_ip`, `filename`
  - primary key: `(date_hour, server_ip, filename)`

- `batches_seen`
  - `sha256`, `received`, `line_count`
  - used for dedup of retried upload batches

- `db_meta`
  - key/value metadata (`last_cleanup`, `last_vacuum`)

## 9) In-Memory State

Receiver keeps these in RAM:

- `_msisdn_hour`: dedup set keyed by `YYYY-MM-DD HH`
- `_msisdn_day`: dedup set keyed by `YYYY-MM-DD`
- `_server_last_seen`: heartbeat timestamp by source server IP

Important:
- raw MSISDN values are not written to SQLite
- only aggregated counts are persisted
- MSISDN state is checkpointed to pickle file

## 10) Endpoints and Curl Examples

All endpoints from current `log-receiver.py` are listed below.

### 10.1 POST /upload

Purpose:
- receive batched log payload from senders

Request body format:
```json
{
  "log": "line1\nline2",
  "host": "sender-host",
  "meta": {
    "start_offset": 123,
    "end_offset": 456,
    "lines": 2,
    "sha256": "..."
  }
}
```

Example:
```bash
curl -X POST http://10.10.23.212:8000/upload \
  -H 'Content-Type: application/json' \
  -d '{"log":"10.0.0.1 - - [26/Jan/2025:14:23:45 +0600] \"GET /ping HTTP/1.1\" 200 10 0.001","host":"test-host","meta":{"lines":1}}'
```

Example success response:
```text
OK - 1 lines
```

Possible response codes:
- `200` success
- `200` duplicate batch accepted as already processed
- `400` invalid input
- `500` write failure (sender should retry)

### 10.2 GET /stats

Purpose:
- return hourly and daily analytics from SQLite

Query params:
- `hours` default `48`
- `days` default `7`

Example:
```bash
curl -s 'http://10.10.23.212:8000/stats?hours=24&days=3' | python3 -m json.tool
```

Example response (trimmed):
```json
{
  "generated_at": "2026-05-06T01:00:00+00:00",
  "hourly_by_server": [],
  "daily_by_server": [],
  "hourly_totals": [],
  "daily_totals": []
}
```

### 10.3 GET /stats/storage

Purpose:
- show DB size, row counts, cleanup/vacuum markers, RAM estimate

Example:
```bash
curl -s http://10.10.23.212:8000/stats/storage | python3 -m json.tool
```

### 10.4 GET /stats/heartbeat

Purpose:
- show last-seen lag per known server
- split into active and silent lists

Example:
```bash
curl -s http://10.10.23.212:8000/stats/heartbeat | python3 -m json.tool
```

### 10.5 GET /dashboard

Purpose:
- return single-page dashboard HTML

Example:
```bash
curl -I http://10.10.23.212:8000/dashboard
```

### 10.6 POST /admin/checkpoint

Purpose:
- force-save MSISDN in-memory state to pickle file

Example:
```bash
curl -s -X POST http://10.10.23.212:8000/admin/checkpoint | python3 -m json.tool
```

### 10.7 POST /admin/vacuum

Purpose:
- trigger manual SQLite VACUUM

Example:
```bash
curl -s -X POST http://10.10.23.212:8000/admin/vacuum | python3 -m json.tool
```

### 10.8 GET or POST /admin/test-email

Purpose:
- trigger immediate SMTP test email

Test message:
```bash
curl -s http://10.10.23.212:8000/admin/test-email | python3 -m json.tool
```

Send report preview:
```bash
curl -s 'http://10.10.23.212:8000/admin/test-email?report=1' | python3 -m json.tool
```

### 10.9 GET /health

Purpose:
- simple liveness probe

Example:
```bash
curl -s http://10.10.23.212:8000/health
```

Expected response:
```text
OK
```

## 11) Deployment Steps (Receiver)

1. copy files to receiver host
2. ensure Python dependencies installed
3. export environment values
4. start Gunicorn with `--preload -w 1`
5. verify `/health`
6. verify `/admin/test-email`

Example:

```bash
scp log-receiver.py alerting.py restart-log-terminal.sh user@10.10.23.212:/app/log-terminal/
ssh user@10.10.23.212
chmod +x /app/log-terminal/restart-log-terminal.sh
/app/log-terminal/restart-log-terminal.sh
curl -s http://10.10.23.212:8000/health
```

## 12) Restart Script

File: `restart-log-terminal.sh`

What it does:
1. exports alerting and SMTP environment values
2. triggers `/admin/checkpoint`
3. stops old Gunicorn via PID file
4. starts Gunicorn daemon
5. checks `State loaded` log line
6. checks `Hourly report scheduler started` log line

## 13) Monitoring Checklist

Run these checks regularly:

```bash
# Receiver alive
curl -sf http://10.10.23.212:8000/health

# Server heartbeat status
curl -s http://10.10.23.212:8000/stats/heartbeat | python3 -m json.tool

# Storage and cleanup status
curl -s http://10.10.23.212:8000/stats/storage | python3 -m json.tool

# Recent errors
grep -E 'ERROR|WARN|alerting' /app/log/access-log-terminal/stats.log | tail -20
```

## 14) Failure and Recovery

### A) Sender stopped on one source server

Symptoms:
- server appears in `silent` list from `/stats/heartbeat`

Actions:
```bash
systemctl status log-shipper
systemctl restart log-shipper
```

### B) Receiver disk write error

Symptoms:
- `/upload` returns `500`
- alert email for write failure

Actions:
- check disk usage
- free space
- verify write permissions for `BASE_LOG_DIR`

### C) SQLite lock or write contention

Symptoms:
- analytics write retries fail
- alert email for analytics DB failure

Actions:
- check for long DB operations
- avoid manual heavy SQLite operations during peak traffic
- run manual vacuum in low traffic windows only

### D) Wrong report hour or timezone mismatch

Symptoms:
- report labeled with unexpected hour/day

Actions:
- set `REPORT_TZ_OFFSET_MINUTES` correctly
- set `REPORT_TZ_LABEL` to expected display value
- restart receiver

### E) All servers shown down

Symptoms:
- hourly report shows all inactive unexpectedly

Actions:
- verify receiver is getting uploads (`/upload` log lines in `stats.log`)
- verify worker runtime threads are started in worker logs
- verify sender reachability to receiver URL

## 15) Quick Command Card

```bash
SERVER=http://10.10.23.212:8000

curl -sf $SERVER/health
curl -s $SERVER/stats | python3 -m json.tool
curl -s $SERVER/stats/storage | python3 -m json.tool
curl -s $SERVER/stats/heartbeat | python3 -m json.tool
curl -s -X POST $SERVER/admin/checkpoint | python3 -m json.tool
curl -s -X POST $SERVER/admin/vacuum | python3 -m json.tool
curl -s $SERVER/admin/test-email | python3 -m json.tool
curl -s "$SERVER/admin/test-email?report=1" | python3 -m json.tool
```

## 16) Notes

- Keep receiver as single worker for consistent in-memory dedup.
- Use graceful restarts to preserve MSISDN state.
- Keep SMTP test endpoint available for operational checks.
- Keep report timezone explicit in environment to avoid date/hour confusion.

End of document.
