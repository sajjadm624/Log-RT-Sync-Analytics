#!/usr/bin/env python3
"""
alerting.py — Email alerting + hourly analytics reports for log-receiver.py

Features
--------
1. Instant alert emails (event-driven, suppressed to 1 per 30 min per event):
   - Server went silent (no uploads for SERVER_SILENT_SECS)
   - Server recovered (resumed uploads after being silent)
   - Write failure on disk
   - Analytics DB repeated failure

2. Scheduled hourly report email (fires at :00 each hour):
   - Executive summary: files received, lines received, active/inactive servers
   - Per-server breakdown with MSISDN counts
   - Yesterday-same-hour comparison (delta + % change)

Configuration (environment variables)
--------------------------------------
  ALERT_EMAIL_ENABLED    0          Set to "1" to enable all email sending
  SMTP_HOST              localhost
  SMTP_PORT              587        587=STARTTLS, 465=SSL, 25=plain
  SMTP_USER                         SMTP username (optional)
  SMTP_PASSWORD                     SMTP password (optional)
  SMTP_USE_TLS           1          STARTTLS (for port 587)
  SMTP_USE_SSL           0          SSL wrapper (for port 465)
  ALERT_FROM             logreceiver@localhost
  ALERT_TO                          Comma-separated recipients (required)
  ALERT_SUPPRESS_SECS    1800       Min seconds between identical alerts
  HOURLY_REPORT_ENABLED  1          Send hourly analytics report
"""

import os
import time
import logging
import smtplib
import sqlite3
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

# ── Runtime import hook — log-receiver sets this after db init ────────────────
# alerting.py calls get_db() and uses DB_PATH / DB_TIMEOUT from log-receiver.
# We accept them as module-level variables that the receiver populates.
DB_PATH    = None   # set by log-receiver after init
DB_TIMEOUT = 30     # set by log-receiver after init

UTC = timezone.utc

# Report timezone controls hour labels and scheduler boundaries.
# Default UTC+6 matches source nginx log clock used in analytics buckets.
REPORT_TZ_OFFSET_MINUTES = int(os.getenv("REPORT_TZ_OFFSET_MINUTES", "360"))
REPORT_TZ = timezone(timedelta(minutes=REPORT_TZ_OFFSET_MINUTES))
_tz_hours = REPORT_TZ_OFFSET_MINUTES // 60
_tz_mins = abs(REPORT_TZ_OFFSET_MINUTES % 60)
REPORT_TZ_LABEL = os.getenv("REPORT_TZ_LABEL", "UTC%+d:%02d" % (_tz_hours, _tz_mins))

# ── Config ────────────────────────────────────────────────────────────────────
EMAIL_ENABLED         = os.getenv("ALERT_EMAIL_ENABLED", "0") not in ("0", "false", "False")
SMTP_HOST             = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT             = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER             = os.getenv("SMTP_USER", "")
SMTP_PASSWORD         = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_TLS          = os.getenv("SMTP_USE_TLS", "1") not in ("0", "false", "False")
SMTP_USE_SSL          = os.getenv("SMTP_USE_SSL", "0") not in ("0", "false", "False")
ALERT_FROM            = os.getenv("ALERT_FROM", "logreceiver@localhost")
ALERT_TO_RAW          = os.getenv("ALERT_TO", "")
ALERT_SUPPRESS_SECS   = int(os.getenv("ALERT_SUPPRESS_SECS", "1800"))
HOURLY_REPORT_ENABLED = os.getenv("HOURLY_REPORT_ENABLED", "1") not in ("0", "false", "False")

ALERT_TO = [a.strip() for a in ALERT_TO_RAW.split(",") if a.strip()]

# ── Suppress table ────────────────────────────────────────────────────────────
# key → unix timestamp of last send for that alert key
_suppress = {}          # type: dict
_suppress_lock = threading.Lock()


def _is_suppressed(key):
    # type: (str) -> bool
    with _suppress_lock:
        last = _suppress.get(key, 0)
        if time.time() - last < ALERT_SUPPRESS_SECS:
            return True
        _suppress[key] = time.time()
        return False


# ── SMTP sender ───────────────────────────────────────────────────────────────

def _send_email(subject, html_body, text_body=None):
    # type: (str, str, str) -> bool
    """
    Send an email via SMTP.  Returns True on success, False on failure.
    No-op (returns True) when EMAIL_ENABLED is False or ALERT_TO is empty.
    """
    if not EMAIL_ENABLED:
        logging.info("[alerting] Email disabled — would send: %s", subject)
        return True
    if not ALERT_TO:
        logging.warning("[alerting] ALERT_TO not configured — cannot send: %s", subject)
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = ALERT_FROM
    msg["To"]      = ", ".join(ALERT_TO)

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if SMTP_USE_SSL:
            conn = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
        else:
            conn = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            if SMTP_USE_TLS:
                conn.starttls()
        if SMTP_USER and SMTP_PASSWORD:
            conn.login(SMTP_USER, SMTP_PASSWORD)
        conn.sendmail(ALERT_FROM, ALERT_TO, msg.as_string())
        conn.quit()
        logging.info("[alerting] Email sent: %s → %s", subject, ALERT_TO)
        return True
    except Exception as exc:
        logging.error("[alerting] Email send failed (%s): %s", subject, exc)
        return False


# ── HTML helpers ──────────────────────────────────────────────────────────────

_CSS = """
body{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:16px}
h2{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:6px;margin:0 0 8px 0;font-size:18px}
h3{color:#8b949e;margin:14px 0 6px 0;font-size:14px}
p{margin:6px 0}
table{border-collapse:collapse;width:100%;margin-top:6px}
th{background:#161b22;color:#8b949e;padding:6px 9px;text-align:left;
    border:1px solid #30363d;font-size:12px}
td{padding:6px 9px;border:1px solid #21262d;font-size:12px}
tr:nth-child(even) td{background:#161b22}
.ok{color:#3fb950}.warn{color:#f0883e}.err{color:#f85149}
.up{color:#3fb950}.dn{color:#f85149}.neu{color:#8b949e}
.badge-active{background:#1a4731;color:#3fb950;padding:1px 7px;border-radius:10px;font-size:10px}
.badge-inactive{background:#3d1a1a;color:#f85149;padding:1px 7px;border-radius:10px;font-size:10px}
.footer{color:#484f58;font-size:11px;margin-top:14px;border-top:1px solid #21262d;padding-top:10px}
.alert-box{border-left:4px solid #f85149;background:#1a0a0a;padding:12px 16px;
           border-radius:4px;margin:12px 0}
.recover-box{border-left:4px solid #3fb950;background:#0a1a0a;padding:12px 16px;
             border-radius:4px;margin:12px 0}
.meta{color:#8b949e;font-size:12px}
.mono{font-family:Consolas,Monaco,monospace}
"""


def _html_wrap(title, body):
    # type: (str, str) -> str
    return (
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<style>" + _CSS + "</style></head><body>"
        "<h2>\U0001f4e1 " + title + "</h2>"
        + body
        + "<div class='footer'>Generated by log-receiver &bull; "
        + datetime.now(REPORT_TZ).strftime("%Y-%m-%d %H:%M:%S ")
        + REPORT_TZ_LABEL
        + "</div></body></html>"
    )


def _fmt_num(n):
    # type: (int) -> str
    if n is None:
        return "—"
    if n >= 1_000_000:
        return "%.2fM" % (n / 1_000_000)
    if n >= 1_000:
        return "%.1fK" % (n / 1_000)
    return str(n)


def _delta_html(now_val, prev_val):
    # type: (int, int) -> str
    """Return coloured +N% / -N% / NEW / — HTML span."""
    if prev_val is None or prev_val == 0:
        if now_val and now_val > 0:
            return "<span class='up'>NEW</span>"
        return "<span class='neu'>—</span>"
    pct = (now_val - prev_val) / prev_val * 100
    sign = "+" if pct >= 0 else ""
    cls = "up" if pct >= 0 else "dn"
    return "<span class='%s'>%s%.1f%%</span>" % (cls, sign, pct)


# ── DB helpers ────────────────────────────────────────────────────────────────

def _get_db():
    if not DB_PATH:
        raise RuntimeError("alerting.DB_PATH not configured")
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _query_hour_stats(date_hour):
    # type: (str) -> list
    """Return list of Row for a given date_hour string 'YYYY-MM-DD HH'."""
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT server_ip, line_count, file_count, unique_msisdns"
            " FROM hourly_stats WHERE date_hour=? ORDER BY server_ip",
            (date_hour,)
        ).fetchall()
        conn.close()
        return rows
    except Exception as exc:
        logging.error("[alerting] DB query error for %s: %s", date_hour, exc)
        return []


def _query_known_servers():
    # type: () -> list
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT DISTINCT server_ip FROM hourly_stats"
            " ORDER BY server_ip"
        ).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception:
        return []


def _query_daily_totals(date_str):
    # type: (str) -> dict
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT COALESCE(SUM(line_count),0) AS lines,"
            " COALESCE(SUM(unique_msisdns),0) AS msisdns,"
            " COUNT(DISTINCT server_ip) AS servers"
            " FROM daily_stats WHERE date=?",
            (date_str,)
        ).fetchone()
        conn.close()
        return {
            "lines": int(row["lines"] or 0),
            "msisdns": int(row["msisdns"] or 0),
            "servers": int(row["servers"] or 0),
        }
    except Exception as exc:
        logging.error("[alerting] DB daily query error for %s: %s", date_str, exc)
        return {"lines": 0, "msisdns": 0, "servers": 0}


# ── Instant alerts ────────────────────────────────────────────────────────────

def alert_server_silent(server_ip, silent_secs):
    # type: (str, float) -> None
    """Call when a known server has not sent logs for silent_secs seconds."""
    key = "silent:" + server_ip
    if _is_suppressed(key):
        return
    mins = int(silent_secs // 60)
    subject = "[LOG ALERT] Server %s silent for %d min" % (server_ip, mins)
    body = (
        "<div class='alert-box'>"
        "<b>\u26a0\ufe0f Server Silent</b><br><br>"
        "Server <b>%s</b> has not sent any log batches for <b>%d minutes</b>.<br>"
        "This may indicate the log-shipper process has stopped, "
        "the server is down, or network connectivity is lost.<br><br>"
        "Please investigate immediately."
        "</div>"
    ) % (server_ip, mins)
    text = "ALERT: Server %s has been silent for %d minutes. Please investigate." % (server_ip, mins)
    threading.Thread(
        target=_send_email, args=(subject, _html_wrap(subject, body), text), daemon=True
    ).start()


def alert_server_recovered(server_ip):
    # type: (str) -> None
    """Call when a previously-silent server resumes sending logs."""
    key = "recovered:" + server_ip
    if _is_suppressed(key):
        return
    # Clear the silent suppression so future silences are alerted again
    with _suppress_lock:
        _suppress.pop("silent:" + server_ip, None)
    subject = "[LOG RECOVERY] Server %s resumed sending logs" % server_ip
    body = (
        "<div class='recover-box'>"
        "<b>\u2705 Server Recovered</b><br><br>"
        "Server <b>%s</b> has resumed sending log batches.<br>"
        "The previous silence alert is now resolved."
        "</div>"
    ) % server_ip
    text = "RECOVERY: Server %s has resumed sending logs." % server_ip
    threading.Thread(
        target=_send_email, args=(subject, _html_wrap(subject, body), text), daemon=True
    ).start()


def alert_write_failure(filepath, error):
    # type: (str, str) -> None
    """Call when a log file write fails on the receiver."""
    key = "write_fail:" + filepath
    if _is_suppressed(key):
        return
    subject = "[LOG ALERT] Write failure on receiver"
    body = (
        "<div class='alert-box'>"
        "<b>\U0001f6a8 Disk Write Failure</b><br><br>"
        "The receiver failed to write to:<br><code>%s</code><br><br>"
        "Error: <code>%s</code><br><br>"
        "Log lines from the shipper will be retried but may cause gaps if "
        "the disk issue persists. Check disk space and permissions immediately."
        "</div>"
    ) % (filepath, error)
    text = "ALERT: Write failure on receiver for %s: %s" % (filepath, error)
    threading.Thread(
        target=_send_email, args=(subject, _html_wrap(subject, body), text), daemon=True
    ).start()


def alert_analytics_failure(error):
    # type: (str) -> None
    """Call when analytics DB write fails after all retries."""
    key = "analytics_fail"
    if _is_suppressed(key):
        return
    subject = "[LOG ALERT] Analytics DB write failed (repeated)"
    body = (
        "<div class='alert-box'>"
        "<b>\U0001f5c4\ufe0f Analytics DB Failure</b><br><br>"
        "The receiver failed to write analytics data after 3 attempts.<br><br>"
        "Error: <code>%s</code><br><br>"
        "Log files are still being written normally. "
        "Analytics counts may have gaps until the DB issue is resolved."
        "</div>"
    ) % error
    text = "ALERT: Analytics DB write failed repeatedly: %s" % error
    threading.Thread(
        target=_send_email, args=(subject, _html_wrap(subject, body), text), daemon=True
    ).start()


# ── Hourly report builder ─────────────────────────────────────────────────────

def build_hourly_report(target_hour_str, server_last_seen, hb_lock, silent_secs_threshold):
    # type: (str, dict, object, int) -> str
    """
    Build the full HTML body for the hourly analytics report.

    target_hour_str     : 'YYYY-MM-DD HH'  — the hour just completed
    server_last_seen    : dict {ip: unix_ts}  from log-receiver
    hb_lock             : threading.Lock protecting server_last_seen
    silent_secs_threshold : SERVER_SILENT_SECS from log-receiver
    """
    # Compute yesterday-same-hour string
    try:
        th_dt = datetime.strptime(target_hour_str, "%Y-%m-%d %H").replace(tzinfo=REPORT_TZ)
        prev_dt = th_dt - timedelta(days=1)
        prev_hour_str = prev_dt.strftime("%Y-%m-%d %H")
    except Exception:
        prev_hour_str = None

    rows_now  = _query_hour_stats(target_hour_str)
    rows_prev = _query_hour_stats(prev_hour_str) if prev_hour_str else []

    report_day = target_hour_str[:10]
    try:
        prev_day = (datetime.strptime(report_day, "%Y-%m-%d") - timedelta(days=1)).strftime("%Y-%m-%d")
    except Exception:
        prev_day = None
    daily_now = _query_daily_totals(report_day)
    daily_prev = _query_daily_totals(prev_day) if prev_day else {"lines": 0, "msisdns": 0, "servers": 0}

    # Build lookup for yesterday {server_ip: row}
    prev_by_server = {r["server_ip"]: r for r in rows_prev}

    # Totals for current hour
    total_lines  = sum(r["line_count"]     for r in rows_now)
    total_files  = sum(r["file_count"]     for r in rows_now)
    total_msisdn = sum(r["unique_msisdns"] for r in rows_now)

    # Totals for previous hour
    prev_total_lines  = sum(r["line_count"]     for r in rows_prev) if rows_prev else None
    prev_total_files  = sum(r["file_count"]     for r in rows_prev) if rows_prev else None
    prev_total_msisdn = sum(r["unique_msisdns"] for r in rows_prev) if rows_prev else None

    # Server activity status
    now_ts = time.time()
    with hb_lock:
        last_seen = dict(server_last_seen)

    known_from_db = _query_known_servers()
    all_servers = sorted(set(known_from_db) | set(last_seen.keys()))

    active_servers   = [ip for ip in all_servers if now_ts - last_seen.get(ip, 0) <= silent_secs_threshold]
    inactive_servers = [ip for ip in all_servers if ip not in active_servers]

    summary_table = (
        "<table>"
        "<tr><th>Window</th><th>Lines</th><th>Files</th><th>Unique MSISDNs</th><th>Active Servers</th><th>Trend</th></tr>"
        "<tr>"
        "<td><b>Hour %s</b></td>"
        "<td class='mono'>%s</td>"
        "<td class='mono'>%s</td>"
        "<td class='mono'>%s</td>"
        "<td class='mono'>%s/%s</td>"
        "<td>%s lines, %s msisdn</td>"
        "</tr>"
        "<tr>"
        "<td><b>Day %s</b></td>"
        "<td class='mono'>%s</td>"
        "<td class='mono'>-</td>"
        "<td class='mono'>%s</td>"
        "<td class='mono'>%s</td>"
        "<td>%s lines, %s msisdn</td>"
        "</tr>"
        "</table>"
    ) % (
        target_hour_str,
        _fmt_num(total_lines),
        _fmt_num(total_files),
        _fmt_num(total_msisdn),
        _fmt_num(len(active_servers)),
        _fmt_num(len(all_servers)),
        _delta_html(total_lines, prev_total_lines),
        _delta_html(total_msisdn, prev_total_msisdn),
        report_day,
        _fmt_num(daily_now["lines"]),
        _fmt_num(daily_now["msisdns"]),
        _fmt_num(daily_now["servers"]),
        _delta_html(daily_now["lines"], daily_prev["lines"]),
        _delta_html(daily_now["msisdns"], daily_prev["msisdns"]),
    )

    # ── Server breakdown table ─────────────────────────────────────────────────
    if rows_now:
        table_rows = ""
        for r in rows_now:
            ip    = r["server_ip"]
            prev  = prev_by_server.get(ip)
            is_active = ip in active_servers
            status_badge = (
                "<span class='badge-active'>Active</span>"
                if is_active else
                "<span class='badge-inactive'>Inactive</span>"
            )
            p_lines  = prev["line_count"]     if prev else None
            p_files  = prev["file_count"]     if prev else None
            p_msisdn = prev["unique_msisdns"] if prev else None

            table_rows += (
                "<tr>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td class='mono'>%s</td>"
                "<td class='mono'>%s</td>"
                "<td class='mono'>%s</td>"
                "<td>%s lines | %s files | %s uniq</td>"
                "</tr>"
            ) % (
                ip,
                status_badge,
                _fmt_num(r["line_count"]),
                _fmt_num(r["file_count"]),
                _fmt_num(r["unique_msisdns"]),
                _delta_html(r["line_count"], p_lines),
                _delta_html(r["file_count"], p_files),
                _delta_html(r["unique_msisdns"], p_msisdn),
            )

        server_table = (
            "<h3>Per-Server Snapshot</h3>"
            "<table>"
            "<tr>"
            "<th>Server IP</th>"
            "<th>Status</th>"
            "<th>Lines</th>"
            "<th>Files</th>"
            "<th>Unique</th>"
            "<th>Vs Yesterday</th>"
            "</tr>"
            + table_rows
            + "</table>"
        )
    else:
        server_table = "<p class='warn'>No data received during this hour.</p>"

    # ── Inactive servers block ────────────────────────────────────────────────
    if inactive_servers:
        inactive_html = (
            "<h3>\u26a0\ufe0f Inactive Servers</h3>"
            "<div class='alert-box'>"
            + ", ".join("<b>%s</b>" % ip for ip in inactive_servers)
            + "<br><small>No uploads received within the last %d seconds.</small>"
            "</div>"
        ) % silent_secs_threshold
    else:
        inactive_html = (
            "<h3>\u2705 All Servers Active</h3>"
            "<div class='recover-box'>All known servers sent logs during this period.</div>"
        )

    # ── Yesterday comparison summary block ───────────────────────────────────
    if prev_hour_str and rows_prev:
        yest_summary = (
            "<h3>\U0001f4c5 Yesterday Same Hour (%s %s)</h3>"
            "<table>"
            "<tr><th>Metric</th><th>Yesterday</th><th>Today</th><th>Change</th></tr>"
            "<tr><td>Log Lines</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            "<tr><td>Files</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            "<tr><td>Unique MSISDNs</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            "</table>"
        ) % (
            prev_hour_str,
            REPORT_TZ_LABEL,
            _fmt_num(prev_total_lines),  _fmt_num(total_lines),  _delta_html(total_lines,  prev_total_lines),
            _fmt_num(prev_total_files),  _fmt_num(total_files),  _delta_html(total_files,  prev_total_files),
            _fmt_num(prev_total_msisdn), _fmt_num(total_msisdn), _delta_html(total_msisdn, prev_total_msisdn),
        )
    elif prev_hour_str:
        yest_summary = (
            "<h3>\U0001f4c5 Yesterday Same Hour (%s %s)</h3>"
            "<p class='neu'>No data available for yesterday's same hour.</p>"
        ) % (prev_hour_str, REPORT_TZ_LABEL)
    else:
        yest_summary = ""

    body = (
        "<p class='meta'>Compact hourly + daily snapshot for <b>%s %s</b></p>"
        "<div>%s</div>"
        "%s"
        "%s"
        "%s"
    ) % (target_hour_str, REPORT_TZ_LABEL, summary_table, yest_summary, server_table, inactive_html)

    return _html_wrap(
        "Hourly Log Analytics — %s %s" % (target_hour_str, REPORT_TZ_LABEL),
        body
    )


def send_hourly_report(target_hour_str, server_last_seen, hb_lock, silent_secs_threshold):
    # type: (str, dict, object, int) -> None
    """Build and send the hourly report. Safe to call in a background thread."""
    if not HOURLY_REPORT_ENABLED:
        return
    try:
        html = build_hourly_report(
            target_hour_str, server_last_seen, hb_lock, silent_secs_threshold
        )
        subject = "[LOG REPORT] Hourly Analytics — %s %s" % (target_hour_str, REPORT_TZ_LABEL)
        text = "Hourly report generated for %s %s." % (target_hour_str, REPORT_TZ_LABEL)
        _send_email(subject, html, text)
    except Exception as exc:
        logging.error("[alerting] Failed to build/send hourly report: %s", exc)


# ── Background scheduler ──────────────────────────────────────────────────────

def _hourly_report_scheduler(get_server_last_seen_fn, hb_lock, silent_secs_threshold):
    """
    Runs in a permanent daemon thread.
    Fires at :15 past each hour (00:15, 01:15, ...).
    The report label uses the current hour (HH).
    get_server_last_seen_fn() must return the current {ip: ts} dict.
    """
    while True:
        now = datetime.now(REPORT_TZ)
        # Compute seconds until the next :15 mark
        if now.minute < 15:
            secs_to_next = (15 - now.minute) * 60 - now.second
        else:
            # Past :15 this hour — wait until :15 of the next hour
            secs_to_next = (60 - now.minute + 15) * 60 - now.second
        time.sleep(max(secs_to_next, 1))

        # Use the current hour label for the :15 report
        completed_hour = datetime.now(REPORT_TZ).replace(minute=0, second=0, microsecond=0)
        target_hour_str = completed_hour.strftime("%Y-%m-%d %H")
        logging.info("[alerting] Firing hourly report for %s %s", target_hour_str, REPORT_TZ_LABEL)

        send_hourly_report(
            target_hour_str,
            get_server_last_seen_fn(),
            hb_lock,
            silent_secs_threshold,
        )


def start_hourly_report_scheduler(get_server_last_seen_fn, hb_lock, silent_secs_threshold):
    # type: (callable, object, int) -> None
    """
    Start the background thread that fires an hourly analytics email.
    Call once from log-receiver.py after DB init completes.
    """
    t = threading.Thread(
        target=_hourly_report_scheduler,
        args=(get_server_last_seen_fn, hb_lock, silent_secs_threshold),
        name="hourly-report",
        daemon=True,
    )
    t.start()
    logging.info("[alerting] Hourly report scheduler started (enabled=%s, to=%s)", HOURLY_REPORT_ENABLED, ALERT_TO)


# ── Silent-server scanner ──────────────────────────────────────────────────────
# Called from log-receiver's background cleanup loop.

_previously_silent = set()   # type: set  tracks servers we already alerted as silent
_ps_lock = threading.Lock()


def scan_server_silence(server_last_seen, hb_lock, silent_secs_threshold, known_servers_list):
    # type: (dict, object, int, list) -> None
    """
    Compare server heartbeats against the silence threshold.
    Fires alert_server_silent for newly-silent servers.
    Fires alert_server_recovered for servers that came back.
    Call periodically (e.g. every 5 min) from the cleanup thread.
    """
    now = time.time()
    with hb_lock:
        last_seen = dict(server_last_seen)

    all_servers = sorted(set(known_servers_list) | set(last_seen.keys()))
    currently_silent = set(
        ip for ip in all_servers
        if now - last_seen.get(ip, 0) > silent_secs_threshold
    )

    with _ps_lock:
        newly_silent    = currently_silent - _previously_silent
        newly_recovered = _previously_silent - currently_silent

        for ip in newly_silent:
            elapsed = now - last_seen.get(ip, 0)
            logging.warning("[alerting] Server %s newly silent (%.0fs)", ip, elapsed)
            threading.Thread(
                target=alert_server_silent,
                args=(ip, elapsed),
                daemon=True,
            ).start()

        for ip in newly_recovered:
            logging.info("[alerting] Server %s recovered", ip)
            threading.Thread(
                target=alert_server_recovered,
                args=(ip,),
                daemon=True,
            ).start()

        _previously_silent.clear()
        _previously_silent.update(currently_silent)
