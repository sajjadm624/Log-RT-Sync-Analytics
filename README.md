# RT-Log-Sync2

Real-time nginx log shipping to a central Flask receiver with:

- raw log persistence (20-minute bucketed files)
- hourly and daily SQLite aggregates
- in-memory MSISDN dedup windows (counts only in DB)
- server heartbeat tracking (active/silent)
- SMTP alerting and hourly email reporting

This README is intentionally aligned with the current code in `log-receiver.py`, `log-shipper.py`, `log_sender-auth_lb.py`, and `alerting.py`.

## 1. Components

- `log-receiver.py`
  - Central Flask app.
  - Accepts `/upload` batches.
  - Writes raw logs to disk by host and time window.
  - Updates hourly/daily analytics in SQLite.
  - Tracks heartbeat and serves dashboard/API/admin routes.

- `alerting.py`
  - SMTP sender and report builder.
  - Sends:
    - silent/recovered server alerts
    - write-failure and analytics-failure alerts
    - scheduled hourly report (at minute 15)

- `log-shipper.py`
  - Standard nginx shipper.
  - Handles multiline continuation fragments safely.
  - Persists byte offset and pending fragment to disk.

- `log_sender-auth_lb.py`
  - Auth-LB JSON shipper.
  - Converts JSON lines into nginx-style text lines before upload.

## 2. High-Level Flow

1. Shipper tails source log using saved offset.
2. It batches lines up to `CHUNK_SIZE` and `MAX_BATCH_BYTES`.
3. It sends JSON payload to receiver `/upload` (gzip by default).
4. Receiver validates payload and checks batch SHA-256 dedup marker.
5. Receiver writes lines into 20-minute files under `BASE_LOG_DIR/<host>/`.
6. Receiver updates:
   - `hourly_stats`
   - `daily_stats`
   - `files_seen`
   - `batches_seen`
7. Receiver updates heartbeat map for source IP.
8. Background loop performs eviction, retention cleanup, checkpoint, silence scan.
9. Alerting scheduler sends hourly report at `:15`.

## 3. Current API Endpoints

- `POST /upload`
- `GET /stats`
- `GET /stats/storage`
- `GET /stats/heartbeat`
- `GET /dashboard`
- `POST /admin/checkpoint`
- `POST /admin/vacuum`
- `GET|POST /admin/test-email` (`?report=1` to send report sample)
- `GET /health`

There are no `/stats/tps*` endpoints in the current receiver code.

## 4. Receiver Environment Variables

All are read in `log-receiver.py`.

- `BASE_LOG_DIR` (default: `/app/log/access-log-terminal/`)
- `ANALYTICS_DB` (default: `/app/log-terminal/analytics.db`)
- `STATE_PATH` (default: `/app/log-terminal/msisdn_state.pkl`)
- `MSISDN_HOUR_WINDOW` (default: `26`)
- `MSISDN_DAY_WINDOW` (default: `2`)
- `CLEANUP_INTERVAL` (default: `3600`)
- `FILES_SEEN_DAYS` (default: `7`)
- `HOURLY_RETAIN_DAYS` (default: `14`)
- `DAILY_RETAIN_DAYS` (default: `90`)
- `BATCH_RETAIN_HOURS` (default: `72`)
- `SERVER_SILENT_SECS` (default: `300`)
- `VACUUM_INTERVAL_HOURS` (default: `168`)
- `KNOWN_SERVERS` (comma-separated list, optional)
- `DB_TIMEOUT` (default: `30`)
- `MAX_CONTENT_LENGTH_MB` (optional upload size cap)
- `PORT` (default: `8000`, used by `python log-receiver.py`)

## 5. Alerting Environment Variables

All are read in `alerting.py`.

- `ALERT_EMAIL_ENABLED` (`0`/`1`)
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_USE_TLS`
- `SMTP_USE_SSL`
- `ALERT_FROM`
- `ALERT_TO` (comma-separated recipients)
- `ALERT_SUPPRESS_SECS` (default: `1800`)
- `HOURLY_REPORT_ENABLED` (default: `1`)
- `REPORT_TZ_OFFSET_MINUTES` (default: `360`)
- `REPORT_TZ_LABEL` (default generated from offset)

## 6. Shipper Environment Variables

Both shippers use this base set:

- `LOG_FILE`
- `OFFSET_FILE`
- `CHUNK_SIZE` (default: `10000`)
- `MAX_BATCH_BYTES` (default: `5242880` = 5 MB)
- `SEND_URL` (default: `http://10.10.23.212:8000/upload`)
- `LOGGING_FILE`
- `POLL_INTERVAL` (default: `0.5`)
- `REQUEST_TIMEOUT_SECS` (default: `15`)
- `USE_GZIP` (default: enabled)
- `SENDER_ID` (optional override for payload `host`)

Standard shipper (`log-shipper.py`) also persists:

- `<OFFSET_FILE>.fragment` for pending multiline continuation data.

## 7. Python Dependencies

- Receiver host:
  - `flask`
  - `gunicorn` (for production serving)

- Sender hosts:
  - `requests`
  - `watchdog`
  - `tenacity`

Install example:

```bash
# Receiver
pip install flask gunicorn

# Sender
pip install requests watchdog tenacity
```

## 8. Receiver Start Example

```bash
gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --pid /app/log-terminal/gunicorn.pid \
  --access-logfile /app/log/access-log-terminal/gunicorn_access.log \
  --error-logfile /app/log/access-log-terminal/gunicorn_error.log
```

Why `-w 1` is recommended:

- MSISDN dedup sets are process-local in memory.
- Multiple workers can inflate unique counts because sets are not shared.

`--preload` also avoids WAL-init races by running DB init before worker fork.

## 9. Shipper Run Example

```bash
python log-shipper.py
```

or

```bash
python log_sender-auth_lb.py
```

Use systemd in production to auto-restart on failure.

## 10. Storage Layout (Receiver)

Under `BASE_LOG_DIR`:

- `stats.log`
- one folder per sender host value (`payload.host`)
- files named:
  - `MyGP_accessLog_<YYMMDDHH>_<00-19|20-39|40-59>_<source_ip_dashed>.log`

SQLite path is `ANALYTICS_DB`.
MSISDN checkpoint path is `STATE_PATH`.

## 11. SQLite Tables (Current)

- `hourly_stats`
- `daily_stats`
- `files_seen`
- `batches_seen`
- `db_meta`

Current schema does not include `url_stats` in this codebase.

## 12. Operations Quick Commands

Health:

```bash
curl http://<receiver>:8000/health
```

Stats:

```bash
curl "http://<receiver>:8000/stats?hours=48&days=7"
curl "http://<receiver>:8000/stats/storage"
curl "http://<receiver>:8000/stats/heartbeat"
```

Manual checkpoint:

```bash
curl -X POST http://<receiver>:8000/admin/checkpoint
```

Manual vacuum:

```bash
curl -X POST http://<receiver>:8000/admin/vacuum
```

SMTP test:

```bash
curl http://<receiver>:8000/admin/test-email
curl http://<receiver>:8000/admin/test-email?report=1
```

## 13. Accuracy Notes

- Receiver writes are fail-fast: if any target file write fails, `/upload` returns `500` so sender retries.
- Batch dedup uses `meta.sha256` and `batches_seen`.
- Source IP for analytics/heartbeat comes from `request.remote_addr`, while host directory name comes from payload `host`.
- MSISDN values are never stored in SQLite, only deduped counts.

## 14. Deep Dive

For internals and code-mapped runtime details, see `DOCUMENTATION.md`.
