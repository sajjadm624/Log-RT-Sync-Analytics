# RT-Log-Sync2 Full Working Documentation

This document explains the full working process of the system in plain language.
It covers architecture, runtime flow, and what each major code block is doing.

## 1. System Goal

RT-Log-Sync2 collects nginx access logs from multiple source servers and sends them to one central receiver.

The receiver does five jobs at the same time:

1. Accept log batches from senders.
2. Write raw logs into host based files.
3. Update hourly and daily analytics in SQLite.
4. Track server heartbeat and silent servers.
5. Send email alerts and scheduled report emails.

## 2. Project Files and Their Responsibilities

- log-shipper.py
  - Standard sender for regular nginx access logs.
  - Reads log file incrementally by byte offset.
  - Sends compressed or plain batches to receiver.

- log_sender-auth_lb.py
  - Sender for auth load balancer JSON log format.
  - Converts JSON records into normalized nginx style lines.

- log-receiver.py
  - Main Flask service.
  - Accepts uploads, writes files, updates analytics, exposes APIs, serves dashboard.

- alerting.py
  - SMTP email engine.
  - Sends instant alerts and scheduled hourly analytics report.

- log_comparison.py and Comparison folder
  - Used for comparison and analysis workflows.

- alerting.py and log-receiver.py together
  - Form the runtime monitoring and reporting path.

## 3. End To End Architecture

### 3.1 Sender Side

Each sender process runs in a loop:

1. Open log file.
2. Read from saved byte offset.
3. Build safe batches based on line count and max bytes.
4. Compute metadata like line count and sha256 fingerprint.
5. POST payload to receiver /upload.
6. If success, move offset forward.
7. If failure, retry without losing data.

Important behavior:

- Rotation safe: if file rotates or truncates, sender detects and recovers.
- Retry safe: same batch can be retried; receiver dedup prevents double counting.
- Partial line safe: continuation handling avoids broken lines when file is updated during read.

### 3.2 Network Payload

Typical payload structure:

```json
{
  "host": "10.10.23.10",
  "log": "line1\nline2\nline3",
  "meta": {
    "start_offset": 100,
    "end_offset": 640,
    "lines": 3,
    "sha256": "batch_fingerprint"
  }
}
```

### 3.3 Receiver Side

When receiver gets /upload:

1. Validate payload.
2. Resolve source host identity.
3. Update heartbeat timestamp for that host.
4. Check dedup table using batch sha256.
5. If new batch, write raw lines into host file path under BASE_LOG_DIR.
6. Parse lines and update hourly and daily SQLite aggregates.
7. Update in memory msisdn dedup sets.
8. Return success.

The receiver stores raw logs and aggregated counters only.
Raw msisdn values are never persisted in SQLite.

## 4. Receiver Runtime Blocks and How They Work

This section maps to major code blocks in log-receiver.py.

### 4.1 Config Block

The top config block reads environment variables.
This controls paths, retention windows, cleanup timing, db timeout, and heartbeat silence threshold.

Examples:

- BASE_LOG_DIR: where raw receiver files are written.
- ANALYTICS_DB: sqlite analytics file path.
- STATE_PATH: checkpoint file for in memory msisdn sets.
- SERVER_SILENT_SECS: threshold to mark a source as silent.

### 4.2 In Memory State Block

Core runtime memory objects:

- _msisdn_hour: set per hour key yyyy-mm-dd hh.
- _msisdn_day: set per day key yyyy-mm-dd.
- _server_last_seen: unix timestamp per server ip.

Why this design:

- Fast dedup inside current rolling windows.
- Privacy and storage efficiency.
- SQLite stores only aggregate numbers, not raw msisdn values.

### 4.3 State Save and Load Block

- _save_state writes current msisdn sets to STATE_PATH using atomic replace.
- _load_state restores on startup and drops stale keys outside configured windows.

This protects continuity after restart so unique counts do not reset abruptly.

### 4.4 SQLite Init Block

init_db creates required tables if missing and enables WAL mode.

Main tables:

- hourly_stats
- daily_stats
- files_seen
- batches_seen
- db_meta

WAL mode allows stable read and write behavior in production.

### 4.5 Analytics Update Block

When a batch is accepted:

1. Merge multiline continuations if needed.
2. Parse timestamp from each line.
3. Build hour and day keys.
4. Upsert line and unique counts into hourly_stats and daily_stats.
5. Track file_count for hourly rows.

Upsert pattern uses insert or ignore plus update for broad sqlite compatibility.

### 4.6 Background Cleanup Block

_cleanup_db runs periodically and removes old data by retention policy.
It also checkpoints WAL and runs vacuum at configured interval.

Other background steps:

- evict old msisdn in memory windows.
- save msisdn checkpoint.
- run silent server scan in alerting module.

### 4.7 Runtime Thread Startup Block

Runtime threads are started once per worker via before_request trigger.
This avoids preload master side effects and duplicate startup.

The startup launches:

- cleanup thread.
- hourly report scheduler thread from alerting.py.

## 5. Alerting Module Blocks and How They Work

This section maps to major code blocks in alerting.py.

### 5.1 SMTP Config and Sender Block

_send_email handles actual SMTP send.

Behavior:

- If email disabled, function returns success as no-op.
- If recipients missing, function returns failure.
- Supports TLS and SSL modes.
- Logs send success or failure details.

### 5.2 Suppression Block

_is_suppressed limits repeated alerts for the same key within ALERT_SUPPRESS_SECS.

This avoids spam for repeated identical failures.

### 5.3 Instant Alert Block

Instant alert functions:

- alert_server_silent
- alert_server_recovered
- alert_write_failure
- alert_analytics_failure

Each one builds message content and sends in a daemon thread.

### 5.4 Hourly Report Builder Block

build_hourly_report creates the full HTML report.

It does these steps:

1. Query current target hour rows.
2. Query previous day same hour rows.
3. Compute totals for lines, files, unique msisdns.
4. Compute active and inactive servers from heartbeat map.
5. Build compact summary table.
6. Build per server snapshot table.
7. Build inactive server section.
8. Return wrapped HTML page.

### 5.5 Scheduler Block

_hourly_report_scheduler is a permanent loop.

Current behavior:

- Fires at minute 15 of every hour.
- Example: 00:15, 01:15, 02:15.
- At fire time, it reports the hour that just completed.

Why minute 15:

- Gives buffer time for delayed uploads after hour change.
- Reduces chance of incomplete report right at minute 00.

## 6. Full Runtime Sequence

This is the full process from startup to steady state.

1. Receiver process starts.
2. Config and paths are loaded.
3. SQLite is initialized.
4. In memory msisdn state is restored from checkpoint.
5. API starts listening.
6. First request triggers runtime threads startup.
7. Sender posts batches to /upload continuously.
8. Receiver writes files and updates analytics.
9. Cleanup loop periodically purges old data and saves state.
10. Silence scan sends alerts for silent or recovered servers.
11. Report scheduler sends compact hourly report at minute 15.

## 7. Data Retention and Storage Lifecycle

Retention controls from environment:

- FILES_SEEN_DAYS
- BATCH_RETAIN_HOURS
- HOURLY_RETAIN_DAYS
- DAILY_RETAIN_DAYS
- MSISDN_HOUR_WINDOW
- MSISDN_DAY_WINDOW

Lifecycle summary:

- Raw files remain under BASE_LOG_DIR unless external cleanup removes them.
- Analytics tables are cleaned by retention logic.
- In memory dedup sets are evicted by rolling windows.
- Periodic checkpoint preserves current dedup state.

## 8. API Overview

Main operational endpoints:

- POST /upload
  - Ingest log batches.

- GET /stats
  - Hourly and daily aggregates.

- GET /stats/storage
  - DB size, row counts, retention markers, memory estimate.

- GET /stats/heartbeat
  - Active and silent server status from heartbeat map.

- GET /dashboard
  - HTML dashboard page.

- POST /admin/checkpoint
  - Force state save.

- POST /admin/vacuum
  - Trigger manual vacuum.

- GET or POST /admin/test-email
  - SMTP test or report preview.

- GET /health
  - Liveness probe.

## 9. Failure Handling Strategy

### 9.1 Sender to Receiver Failures

- Sender retries with backoff.
- Offset is not advanced until successful send.
- This preserves at least once delivery behavior.

### 9.2 Duplicate Batch Delivery

- Receiver uses batches_seen with sha256 key.
- Duplicate retries are accepted but not counted twice.

### 9.3 Receiver Disk Write Failure

- Receiver logs the failure.
- alert_write_failure can send instant email.

### 9.4 Analytics Write Failure

- Receiver retries internal DB operations.
- alert_analytics_failure sends warning if repeated failures continue.

### 9.5 Receiver Restart

- msisdn state reload keeps unique counting continuity.
- cleanup and scheduler threads restart automatically.

## 10. Environment Variables Quick Reference

### Receiver and Runtime

- BASE_LOG_DIR
- ANALYTICS_DB
- STATE_PATH
- MSISDN_HOUR_WINDOW
- MSISDN_DAY_WINDOW
- CLEANUP_INTERVAL
- FILES_SEEN_DAYS
- HOURLY_RETAIN_DAYS
- DAILY_RETAIN_DAYS
- BATCH_RETAIN_HOURS
- SERVER_SILENT_SECS
- VACUUM_INTERVAL_HOURS
- KNOWN_SERVERS
- DB_TIMEOUT
- MAX_CONTENT_LENGTH_MB

### Alerting and SMTP

- ALERT_EMAIL_ENABLED
- SMTP_HOST
- SMTP_PORT
- SMTP_USER
- SMTP_PASSWORD
- SMTP_USE_TLS
- SMTP_USE_SSL
- ALERT_FROM
- ALERT_TO
- ALERT_SUPPRESS_SECS
- HOURLY_REPORT_ENABLED
- REPORT_TZ_OFFSET_MINUTES
- REPORT_TZ_LABEL

### Sender

- LOG_FILE
- OFFSET_FILE
- CHUNK_SIZE
- MAX_BATCH_BYTES
- SEND_URL
- LOGGING_FILE
- POLL_INTERVAL
- REQUEST_TIMEOUT_SECS
- USE_GZIP
- SENDER_ID

## 11. Practical Validation Checklist

1. Start receiver and verify /health returns OK.
2. Send one small test payload to /upload.
3. Check raw file write under BASE_LOG_DIR.
4. Check /stats for hourly and daily row updates.
5. Check /stats/heartbeat for source server activity.
6. Trigger /admin/test-email and verify SMTP path.
7. Trigger /admin/test-email?report=1 to preview report format.
8. Wait for minute 15 scheduler and verify automatic report delivery.

## 12. Summary

The system is designed for reliable log transport, deduplicated ingest, rolling analytics, and operational visibility.
The sender side protects data continuity with offset and retry logic.
The receiver side protects consistency with dedup, SQLite upserts, checkpointed in memory dedup state, and scheduled monitoring emails.
The alerting side provides both immediate fault notifications and regular compact reporting.
