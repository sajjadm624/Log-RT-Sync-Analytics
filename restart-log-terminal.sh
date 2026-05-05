#!/bin/bash

# ── Email alerting config ─────────────────────────────────────────────────────
export ALERT_EMAIL_ENABLED=1
export ALERT_TO="sazzad.manik@miaki.com.bd"
export SMTP_HOST="192.168.207.212"
export SMTP_PORT=25
export SMTP_USE_TLS=0
export SMTP_USE_SSL=0
export SMTP_USER="mygp@grameenphone.com"
export SMTP_PASSWORD=""
export ALERT_FROM="mygp@grameenphone.com"
export ALERT_SUPPRESS_SECS=1800
export HOURLY_REPORT_ENABLED=1
export REPORT_TZ_OFFSET_MINUTES=360
export REPORT_TZ_LABEL="UTC+06:00"
# ─────────────────────────────────────────────────────────────────────────────

echo "=== Triggering checkpoint ==="
curl -s -X POST http://10.10.23.212:8000/admin/checkpoint | python3 -m json.tool

echo "=== Stopping Gunicorn ==="
if [ -f /app/log-terminal/gunicorn.pid ]; then
    kill -TERM $(cat /app/log-terminal/gunicorn.pid)
else
    echo "PID file not found."
fi

echo "=== Waiting for shutdown ==="
sleep 5

echo "=== Starting Gunicorn ==="
cd /app/log-terminal || exit 1

gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \
  --daemon \
  --pid /app/log-terminal/gunicorn.pid

echo "=== Checking last state load ==="
grep "State loaded" /app/log/access-log-terminal/stats.log | tail -1

echo "=== Checking alerting scheduler started ==="
sleep 2
grep "Hourly report scheduler started" /app/log/access-log-terminal/stats.log | tail -1

echo "=== Done ==="
