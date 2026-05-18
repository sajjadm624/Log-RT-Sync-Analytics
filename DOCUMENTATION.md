# RT-Log-Sync2 Technical Documentation (Code-Aligned)

This document is a full technical reference for the current codebase.
It is intentionally aligned to the actual implementation in:

- `log-receiver.py`
- `alerting.py`
- `log-shipper.py`
- `log_sender-auth_lb.py`

If behavior in code changes, this document must be updated accordingly.

## 1. System Purpose

RT-Log-Sync2 ingests nginx logs from multiple source servers into one central receiver.

The receiver performs, in one runtime:

1. Batch ingest (`/upload`).
2. Raw file persistence (bucketed by hour + 20-minute windows).
3. SQLite aggregate maintenance (hourly/daily counts).
4. Heartbeat tracking (active vs silent servers).
5. Email alerting and scheduled hourly report delivery.

## 2. Runtime Architecture

### 2.1 Sender side

Two shipper variants are in this repository:

- `log-shipper.py`:
  - tails a standard nginx access log
  - supports continuation-fragment reassembly for multiline splits
  - stores both byte offset and pending fragment

- `log_sender-auth_lb.py`:
  - tails JSON lines from auth LB
  - converts each JSON object into nginx-style text line
  - continuation handling is not needed because source is one JSON object per physical line

Both send to receiver with payload:

```json
{
  "host": "sender_identity",
  "log": "line1\nline2\n...",
  "meta": {
    "start_offset": 0,
    "end_offset": 1234,
    "file_id": [dev, inode],
    "lines": 100,
    "sha256": "batch_fingerprint"
  }
}
```

### 2.2 Receiver side

In `log-receiver.py`, `/upload` does:

1. Parse JSON body (gzip or plain).
2. Validate required fields (`log`, `host`).
3. Check batch idempotency by `meta.sha256` against `batches_seen`.
4. Split and normalize lines (merge continuation fragments receiver-side too).
5. Determine target files by parsed timestamp (or receipt time fallback):
   - `00-19`, `20-39`, `40-59` minute windows.
6. Write all file batches with fsync.
7. Update heartbeat map using `request.remote_addr`.
8. Update analytics (`hourly_stats`, `daily_stats`, `files_seen`) with retry loop.
9. Persist `batches_seen` marker for future dedup.

If file write fails, endpoint returns `500` so sender retries.

## 3. Receiver Configuration (Current)

Read from environment in `log-receiver.py`.

### 3.1 Paths and DB

- `BASE_LOG_DIR` (default `/app/log/access-log-terminal/`)
- `ANALYTICS_DB` (default `/app/log-terminal/analytics.db`)
- `STATE_PATH` (default `/app/log-terminal/msisdn_state.pkl`)

### 3.2 Windows and retention

- `MSISDN_HOUR_WINDOW` (default `26`)
- `MSISDN_DAY_WINDOW` (default `2`)
- `CLEANUP_INTERVAL` (default `3600`)
- `FILES_SEEN_DAYS` (default `7`)
- `HOURLY_RETAIN_DAYS` (default `14`)
- `DAILY_RETAIN_DAYS` (default `90`)
- `BATCH_RETAIN_HOURS` (default `72`)
- `VACUUM_INTERVAL_HOURS` (default `168`)

### 3.3 Heartbeat and operational

- `SERVER_SILENT_SECS` (default `300`)
- `KNOWN_SERVERS` (comma-separated; optional)
- `DB_TIMEOUT` (default `30`)
- `MAX_CONTENT_LENGTH_MB` (optional)
- `PORT` (default `8000`, only for Flask dev run)

## 4. In-Memory State and Persistence

### 4.1 MSISDN dedup maps

- `_msisdn_hour`: `date_hour -> set(msisdn)`
- `_msisdn_day`: `date -> set(msisdn)`

Only counts are persisted to SQLite. Raw MSISDN values are never stored in DB.

### 4.2 State checkpoint

- `_save_state()` writes atomic pickle to `STATE_PATH`.
- `_load_state()` restores and drops stale windows older than configured cutoffs.

### 4.3 Signal hooks

- `SIGTERM`: attempts state save before exit.
- `SIGHUP`: triggers asynchronous save.

## 5. SQLite Layer

### 5.1 Initialization

`init_db()` enables:

- `PRAGMA journal_mode=WAL`
- `PRAGMA synchronous=NORMAL`
- `PRAGMA auto_vacuum=INCREMENTAL`

### 5.2 Tables created by current code

- `hourly_stats(date_hour, server_ip, line_count, file_count, unique_msisdns)`
- `daily_stats(date, server_ip, line_count, unique_msisdns)`
- `files_seen(date_hour, server_ip, filename)`
- `batches_seen(sha256, received, line_count)`
- `db_meta(key, value)`

Indexes:

- `idx_hourly_date` on `hourly_stats(date_hour)`
- `idx_daily_date` on `daily_stats(date)`
- `idx_batches_ts` on `batches_seen(received)`

Important: current receiver code does not define a `url_stats` table or TPS endpoints.

### 5.3 Write pattern

Upsert logic uses:

- `INSERT OR IGNORE`
- followed by `UPDATE`

This is compatible with older SQLite versions.

## 6. Analytics Update Logic

`_record_analytics(lines, server_ip, receipt_dt, files_written)`:

1. Parse each line timestamp (or use `receipt_dt` fallback).
2. Build per-hour and per-day line counters.
3. Extract MSISDN via regex from line content.
4. Compute net-new MSISDN deltas against in-memory sets.
5. Upsert hourly and daily counts.
6. For each output filename, insert into `files_seen` and increment hourly `file_count` once per new file record.

## 7. Background Runtime Threads

Threads are started once per worker via `@app.before_request` and `_ensure_runtime_threads_started()`.

### 7.1 Cleanup thread (`_background_cleanup`)

Runs every `CLEANUP_INTERVAL` and executes:

1. `_evict_old_msisdn_sets()`
2. `_cleanup_db()`
3. `_save_state()`
4. `alerting.scan_server_silence(...)`

### 7.2 `_cleanup_db()` retention actions

Deletes old rows from:

- `files_seen` by `FILES_SEEN_DAYS`
- `batches_seen` by `BATCH_RETAIN_HOURS`
- `hourly_stats` by `HOURLY_RETAIN_DAYS`
- `daily_stats` by `DAILY_RETAIN_DAYS`

Also:

- updates `db_meta.last_cleanup`
- performs `PRAGMA wal_checkpoint(TRUNCATE)`
- performs periodic `VACUUM` based on `VACUUM_INTERVAL_HOURS`
- records `db_meta.last_vacuum`

### 7.3 Hourly report scheduler thread

Started by `alert.start_hourly_report_scheduler(...)`.

Current behavior in `alerting.py`:

- waits to minute `15` each hour
- builds report label for current hour floor (`YYYY-MM-DD HH`)
- sends report via SMTP if enabled

## 8. Alerting Module Behavior

`alerting.py` provides both instant alerts and scheduled reporting.

### 8.1 SMTP sender

`_send_email()`:

- no-op success when email disabled
- fails when recipient list is missing
- supports TLS (`SMTP_USE_TLS`) and SSL (`SMTP_USE_SSL`)

### 8.2 Suppression

`_is_suppressed(key)` blocks repeated sends within `ALERT_SUPPRESS_SECS`.

### 8.3 Instant alerts

- `alert_server_silent(server_ip, silent_secs)`
- `alert_server_recovered(server_ip)`
- `alert_write_failure(filepath, error)`
- `alert_analytics_failure(error)`

### 8.4 Hourly report

`build_hourly_report(...)` includes:

- hourly totals (lines, files, unique msisdns)
- active/inactive server summary
- per-server breakdown table
- yesterday-same-hour comparison
- daily summary comparison

Timezone controls:

- `REPORT_TZ_OFFSET_MINUTES`
- `REPORT_TZ_LABEL`

## 9. Heartbeat and Server Silence

Receiver updates `_server_last_seen[source_ip]` on successful upload processing.

`/stats/heartbeat` reports:

- `servers`: seconds since last seen per IP
- `known_servers`
- `active`
- `silent`
- `silent_secs`

Known server source:

1. `KNOWN_SERVERS` env (if set), otherwise
2. auto-discover from DB + live heartbeat keys.

## 10. Dashboard (Current)

`/dashboard` returns one inline HTML page with JS/CSS and auto-refresh every 60 seconds.

Tabs currently rendered:

1. Overview
2. By Server
3. Yesterday vs Today
4. HAU & DAU
5. Daily Summary
6. Server Health
7. Storage Health

Data sources used by dashboard:

- `/stats?hours=48&days=7`
- `/stats/storage`
- `/stats/heartbeat`

## 11. API Reference (Current)

### 11.1 `POST /upload`

Accepts JSON or gzip-compressed JSON payload with keys `log`, `host`, optional `meta`.

Responses:

- `200` on success (`OK - N lines`)
- `200` for duplicate batch SHA (`already processed`)
- `400` for invalid payload
- `500` when file write fails (to force sender retry)

### 11.2 `GET /stats`

Query params:

- `hours` (default `48`)
- `days` (default `7`)

Returns:

- `hourly_by_server`
- `daily_by_server`
- `hourly_totals`
- `daily_totals`

### 11.3 `GET /stats/storage`

Returns DB file size, row counts, cleanup/vacuum timestamps, and in-memory MSISDN estimates.

### 11.4 `GET /stats/heartbeat`

Returns heartbeat age map and active/silent classification.

### 11.5 `GET /dashboard`

Returns analytics dashboard HTML.

### 11.6 `POST /admin/checkpoint`

Forces `_save_state()` and returns saved counts/status.

### 11.7 `POST /admin/vacuum`

Runs manual checkpoint+VACUUM flow and returns before/after size.

### 11.8 `GET|POST /admin/test-email`

- plain test email by default
- `?report=1` sends hourly report sample

### 11.9 `GET /health`

Simple liveness endpoint returning `OK`.

## 12. Sender Details

### 12.1 `log-shipper.py`

Key behaviors:

- offset persistence: `OFFSET_FILE`
- pending continuation persistence: `OFFSET_FILE.fragment`
- inode-aware rotation handling (drain old file then switch)
- truncation handling (reset offset)
- line filter for health-check noise (`/health.php`, `nginx/`, `health check`)
- retries via `tenacity` (`600` attempts, `6` second wait)

### 12.2 `log_sender-auth_lb.py`

Key behaviors:

- per-line JSON parse and conversion to nginx-style line
- skip internal auth probe lines (`/_auth_verify` + `nginx/` + `/_auth_js`)
- same batch transport and retry pattern as standard shipper

## 13. Recommended Deployment Notes

### 13.1 Gunicorn

Use:

- `--preload`
- `-w 1`

Reasoning:

- `--preload` avoids multi-worker WAL init races.
- `-w 1` avoids in-memory MSISDN dedup divergence across worker processes.

### 13.2 File and DB ownership

Ensure receiver process user can write:

- `BASE_LOG_DIR`
- directory containing `ANALYTICS_DB`
- directory containing `STATE_PATH`

### 13.3 Sender service mode

Run shippers under systemd/supervisor for auto-restart.

## 14. Validation Checklist

1. Receiver liveness:
   - `GET /health` returns `OK`.
2. Upload path:
   - send test payload to `/upload`.
3. Raw file write:
   - verify file appears under `BASE_LOG_DIR/<host>/`.
4. Aggregates:
   - verify `/stats` returns hourly/daily rows.
5. Heartbeat:
   - verify `/stats/heartbeat` updates source IP age.
6. Storage health:
   - verify `/stats/storage` row counts and timestamps.
7. Email path:
   - call `/admin/test-email`.
8. Report preview:
   - call `/admin/test-email?report=1`.

## 15. Known Operational Constraints

1. MSISDN dedup correctness relies on single worker process memory view.
2. Raw log files are append-only and not auto-pruned by receiver code.
3. VACUUM can lock DB during execution (manual or scheduled).
4. If process is terminated ungracefully, in-memory state can roll back to last successful checkpoint.

## 16. Quick Command Snippets

```bash
# health
curl http://<receiver>:8000/health

# stats
curl "http://<receiver>:8000/stats?hours=48&days=7"

# storage
curl "http://<receiver>:8000/stats/storage"

# heartbeat
curl "http://<receiver>:8000/stats/heartbeat"

# checkpoint
curl -X POST http://<receiver>:8000/admin/checkpoint

# vacuum
curl -X POST http://<receiver>:8000/admin/vacuum

# test email
curl http://<receiver>:8000/admin/test-email

# report sample email
curl http://<receiver>:8000/admin/test-email?report=1
```

## 17. Change Control Note

When modifying receiver or sender behavior, update this document and `README.md` in the same commit so documentation remains code-accurate.
