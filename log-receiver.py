"""
log-receiver.py  —  Flask log receiver with storage-efficient analytics
========================================================================

GUNICORN USAGE:
    gunicorn --preload -w 1 -b 0.0.0.0:8000 log-receiver:app \\
        --daemon \\
        --pid /app/log-terminal/gunicorn.pid

CRITICAL FLAGS:
    --preload   Loads the app ONCE in the master process before forking
                workers. This means init_db() runs exactly once, avoiding
                the "database is locked" race on startup.

    -w 1        Keep workers at 1. Each worker holds its OWN in-memory
                MSISDN sets (processes do not share memory). More workers
                = the same MSISDN seen by two workers gets counted twice.
                1 worker is the correct balance: handles requests
                and writes to DB.

Storage strategy:
    Individual MSISDNs are NEVER written to disk.
    In-memory Python sets dedup within a rolling window.
    Only integer counts are flushed to SQLite.
    DB grows ~14 MB/year and stays under ~70 MB forever.
"""

from flask import Flask, request, jsonify, Response
import os
import logging
import json
import gzip
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List

# Python 3.6 compatibility: timezone is in datetime module
try:
    from datetime import timezone
    UTC = timezone.utc
except ImportError:
    import pytz
    UTC = pytz.utc

# ── config ────────────────────────────────────────────────────────────────────
app = Flask(__name__)

BASE_LOG_DIR  = os.getenv("BASE_LOG_DIR",  "/app/log/access-log-terminal/")
META_LOG_FILE = os.path.join(BASE_LOG_DIR, "stats.log")
DB_PATH       = os.getenv("ANALYTICS_DB",  "/app/log-terminal/analytics.db")

MSISDN_HOUR_WINDOW = int(os.getenv("MSISDN_HOUR_WINDOW", "26"))
MSISDN_DAY_WINDOW  = int(os.getenv("MSISDN_DAY_WINDOW",  "2"))
CLEANUP_INTERVAL   = int(os.getenv("CLEANUP_INTERVAL",   "3600"))
FILES_SEEN_DAYS    = int(os.getenv("FILES_SEEN_DAYS",     "7"))

# SQLite connection timeout — workers wait up to this many seconds for a lock.
# With 2 workers this is almost never hit; kept generous for safety.
DB_TIMEOUT = int(os.getenv("DB_TIMEOUT", "30"))

os.makedirs(BASE_LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

_max_mb = os.getenv("MAX_CONTENT_LENGTH_MB")
if _max_mb:
    try:
        app.config["MAX_CONTENT_LENGTH"] = int(float(_max_mb) * 1024 * 1024)
    except Exception:
        pass

logging.basicConfig(
    filename=META_LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# ── patterns ──────────────────────────────────────────────────────────────────
nginx_ts_pat     = re.compile(r"\[(\d{2}/[A-Za-z]+/\d{4}:\d{2}:\d{2}:\d{2})")
msisdn_pat       = re.compile(r'(?:\\x22|")msisdn(?:\\x22|"):(?:\\x22|")(\d{7,15})')
NGINX_LINE_START = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})\s")
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3,  "Apr": 4,  "May": 5,  "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9,  "Oct": 10, "Nov": 11, "Dec": 12,
}

# ── in-memory MSISDN dedup (per-worker, never written to disk) ────────────────
_msisdn_hour = {}   # type: Dict[str, set]  date_hour → set of MSISDNs
_msisdn_day  = {}   # type: Dict[str, set]  date      → set of MSISDNs
_mem_lock    = threading.Lock()


def _mem_stats():
    with _mem_lock:
        h_sets  = len(_msisdn_hour)
        h_total = sum(len(s) for s in _msisdn_hour.values())
        d_sets  = len(_msisdn_day)
        d_total = sum(len(s) for s in _msisdn_day.values())
    est_mb = (h_total + d_total) * 56 / 1e6
    return {
        "hour_sets":        h_sets,
        "hour_msisdns":     h_total,
        "day_sets":         d_sets,
        "day_msisdns":      d_total,
        "estimated_ram_mb": round(est_mb, 1),
    }


def _evict_old_msisdn_sets():
    now = datetime.now(UTC)
    cutoff_h = (now - timedelta(hours=MSISDN_HOUR_WINDOW)).strftime("%Y-%m-%d %H")
    cutoff_d = (now - timedelta(days=MSISDN_DAY_WINDOW)).strftime("%Y-%m-%d")
    with _mem_lock:
        stale_h = [k for k in _msisdn_hour if k < cutoff_h]
        stale_d = [k for k in _msisdn_day  if k < cutoff_d]
        for k in stale_h:
            del _msisdn_hour[k]
        for k in stale_d:
            del _msisdn_day[k]
    if stale_h or stale_d:
        logging.info(
            "Evicted %d hour-set(s) and %d day-set(s) from in-memory MSISDN store.",
            len(stale_h), len(stale_d)
        )


# ── SQLite ─────────────────────────────────────────────────────────────────────
# _db_lock serialises writes within a single worker process.
# Across workers, SQLite WAL mode allows concurrent readers + one writer.
_db_lock = threading.Lock()


def _get_db():
    """
    Open a per-call SQLite connection.
    WAL mode is set in init_db() once; we do NOT set it here to avoid
    the exclusive-lock race when multiple workers start simultaneously.
    """
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Only set synchronous — safe to repeat, needs no exclusive lock.
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    """
    Run ONCE — either at module load with --preload (before workers fork)
    or in the first worker to start.

    Sets WAL mode (requires brief exclusive lock) and creates tables.
    With --preload this runs in the master process before any worker forks,
    so there is never a race.
    """
    try:
        conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hourly_stats (
                date_hour      TEXT NOT NULL,
                server_ip      TEXT NOT NULL,
                line_count     INTEGER DEFAULT 0,
                file_count     INTEGER DEFAULT 0,
                unique_msisdns INTEGER DEFAULT 0,
                PRIMARY KEY (date_hour, server_ip)
            );
            CREATE TABLE IF NOT EXISTS daily_stats (
                date           TEXT NOT NULL,
                server_ip      TEXT NOT NULL,
                line_count     INTEGER DEFAULT 0,
                unique_msisdns INTEGER DEFAULT 0,
                PRIMARY KEY (date, server_ip)
            );
            CREATE TABLE IF NOT EXISTS files_seen (
                date_hour TEXT NOT NULL,
                server_ip TEXT NOT NULL,
                filename  TEXT NOT NULL,
                PRIMARY KEY (date_hour, server_ip, filename)
            );
            CREATE TABLE IF NOT EXISTS db_meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_hourly_date ON hourly_stats(date_hour);
            CREATE INDEX IF NOT EXISTS idx_daily_date  ON daily_stats(date);
        """)
        conn.commit()
        conn.close()
        logging.info("init_db() complete. WAL mode enabled.")
    except sqlite3.OperationalError as e:
        # Another worker beat us to it — WAL already set, tables already exist.
        # This is safe to ignore.
        logging.warning("init_db() skipped (already initialised by another process): %s", e)


# Run at import time.
# With --preload: runs once in master before workers fork → no race.
# Without --preload: each worker runs it; the threading.Lock + SQLite
# timeout handle the brief contention.
init_db()

# ── background cleanup (one thread per worker) ────────────────────────────────

def _cleanup_db():
    cutoff = (datetime.now(UTC) - timedelta(days=FILES_SEEN_DAYS)).strftime("%Y-%m-%d")
    try:
        conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
        conn.execute("PRAGMA synchronous=NORMAL")
        cur = conn.execute(
            "DELETE FROM files_seen WHERE date_hour < ?",
            (cutoff + " 00",)
        )
        deleted = cur.rowcount
        conn.execute(
            "INSERT OR REPLACE INTO db_meta(key,value) VALUES('last_cleanup',?)",
            (datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00"),)
        )
        conn.commit()
        conn.close()
        if deleted:
            logging.info("DB cleanup: removed %d old files_seen rows.", deleted)
        # VACUUM outside the main write connection.
        conn2 = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
        conn2.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn2.execute("VACUUM")
        conn2.close()
        logging.info("DB VACUUM complete.")
    except Exception as e:
        logging.error("DB cleanup error: %s", e)


def _background_cleanup():
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            _evict_old_msisdn_sets()
            _cleanup_db()
        except Exception as e:
            logging.error("Background cleanup failed: %s", e)


threading.Thread(
    target=_background_cleanup, name="cleanup", daemon=True
).start()

# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_nginx_dt(line):
    m = nginx_ts_pat.search(line)
    if not m:
        return None
    try:
        raw = m.group(1)
        p   = raw.replace("/", " ").replace(":", " ").split()
        return datetime(
            int(p[2]), MONTHS[p[1]], int(p[0]),
            int(p[3]), int(p[4]), int(p[5]),
            tzinfo=UTC
        )
    except Exception:
        return None


def _merge_continuations(text):
    # type: (str) -> List[str]
    """Rejoin lines split by embedded newlines in nginx JSON fields."""
    merged = []
    for line in text.splitlines():
        if not line:
            continue
        if NGINX_LINE_START.match(line):
            merged.append(line)
        elif merged:
            merged[-1] += line
        else:
            merged.append(line)
    return merged


def _upsert_hourly(conn, dh, server_ip, line_cnt, msisdn_delta):
    """
    Python 3.6 / SQLite 3.24-safe upsert for hourly_stats.
    Uses INSERT OR IGNORE + UPDATE instead of ON CONFLICT DO UPDATE,
    which requires SQLite 3.24+ (not guaranteed on all 3.6 installs).
    """
    conn.execute(
        "INSERT OR IGNORE INTO hourly_stats"
        "(date_hour,server_ip,line_count,file_count,unique_msisdns)"
        " VALUES(?,?,0,0,0)",
        (dh, server_ip)
    )
    conn.execute(
        "UPDATE hourly_stats SET line_count=line_count+?, unique_msisdns=unique_msisdns+?"
        " WHERE date_hour=? AND server_ip=?",
        (line_cnt, msisdn_delta, dh, server_ip)
    )


def _upsert_daily(conn, day, server_ip, line_cnt, msisdn_delta):
    conn.execute(
        "INSERT OR IGNORE INTO daily_stats(date,server_ip,line_count,unique_msisdns)"
        " VALUES(?,?,0,0)",
        (day, server_ip)
    )
    conn.execute(
        "UPDATE daily_stats SET line_count=line_count+?, unique_msisdns=unique_msisdns+?"
        " WHERE date=? AND server_ip=?",
        (line_cnt, msisdn_delta, day, server_ip)
    )


def _upsert_file_count(conn, dh_f, server_ip):
    conn.execute(
        "INSERT OR IGNORE INTO hourly_stats"
        "(date_hour,server_ip,line_count,file_count,unique_msisdns)"
        " VALUES(?,?,0,0,0)",
        (dh_f, server_ip)
    )
    conn.execute(
        "UPDATE hourly_stats SET file_count=file_count+1"
        " WHERE date_hour=? AND server_ip=?",
        (dh_f, server_ip)
    )


def _record_analytics(lines, server_ip, receipt_dt, files_written):
    # type: (List[str], str, datetime, Dict[str, int]) -> None
    hourly_lines = {}  # type: Dict[str, int]
    daily_lines  = {}  # type: Dict[str, int]
    new_h        = {}  # type: Dict[str, set]
    new_d        = {}  # type: Dict[str, set]

    for line in lines:
        dt  = _parse_nginx_dt(line) or receipt_dt
        dh  = dt.strftime("%Y-%m-%d %H")
        day = dt.strftime("%Y-%m-%d")
        hourly_lines[dh]  = hourly_lines.get(dh,  0) + 1
        daily_lines[day]  = daily_lines.get(day, 0) + 1
        for msisdn in msisdn_pat.findall(line):
            new_h.setdefault(dh,  set()).add(msisdn)
            new_d.setdefault(day, set()).add(msisdn)

    # Dedup MSISDNs in-memory; persist only the net-new count.
    hour_deltas = {}  # type: Dict[str, int]
    day_deltas  = {}  # type: Dict[str, int]
    with _mem_lock:
        for dh, msisdns in new_h.items():
            ex = _msisdn_hour.setdefault(dh, set())
            nn = msisdns - ex
            ex.update(nn)
            hour_deltas[dh] = len(nn)
        for day, msisdns in new_d.items():
            ex = _msisdn_day.setdefault(day, set())
            nn = msisdns - ex
            ex.update(nn)
            day_deltas[day] = len(nn)

    try:
        with _db_lock:
            conn = _get_db()
            try:
                for dh, cnt in hourly_lines.items():
                    _upsert_hourly(conn, dh, server_ip, cnt, hour_deltas.get(dh, 0))

                for day, cnt in daily_lines.items():
                    _upsert_daily(conn, day, server_ip, cnt, day_deltas.get(day, 0))

                for filepath in files_written:
                    fname = os.path.basename(filepath)
                    fm    = re.search(r"_(\d{8})_", fname)
                    dh_f  = receipt_dt.strftime("%Y-%m-%d %H")
                    if fm:
                        try:
                            ts   = fm.group(1)
                            dh_f = "20%s-%s-%s %s" % (
                                ts[0:2], ts[2:4], ts[4:6], ts[6:8]
                            )
                        except Exception:
                            pass
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO files_seen"
                        "(date_hour,server_ip,filename) VALUES(?,?,?)",
                        (dh_f, server_ip, fname)
                    )
                    if cur.rowcount:
                        _upsert_file_count(conn, dh_f, server_ip)

                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        logging.error("Analytics DB write failed: %s", e)


# ── /upload ───────────────────────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
def upload():
    payload = None
    try:
        if request.headers.get("Content-Encoding", "").lower() == "gzip":
            raw     = gzip.decompress(request.get_data(cache=False))
            payload = json.loads(raw.decode("utf-8", errors="replace"))
        else:
            if not request.is_json:
                return "Invalid content-type", 400
            payload = request.get_json(silent=True)
    except Exception as e:
        logging.warning("Parse error: %s", e)
        return "Invalid JSON", 400

    if not isinstance(payload, dict):
        return "Invalid JSON", 400

    log_data  = payload.get('log')
    hostname  = payload.get('host')
    meta      = payload.get('meta') or {}
    # Keep dotted form for DB storage; use dashed only in filenames
    source_ip       = (request.remote_addr or "unknown")
    source_ip_dashed = source_ip.replace(".", "-")

    if not log_data or not hostname:
        return "Missing data", 400

    host_dir = os.path.join(BASE_LOG_DIR, hostname.strip())
    os.makedirs(host_dir, exist_ok=True)

    lines      = _merge_continuations(str(log_data))
    receipt_dt = datetime.now(UTC)
    file_batches = {}  # type: Dict[str, List[str]]
    unparsed   = 0

    for line in lines:
        if not line:
            continue
        dt = _parse_nginx_dt(line)
        if dt is None:
            dt = receipt_dt
            unparsed += 1
        minute = dt.minute
        window = "00-19" if minute < 20 else "20-39" if minute < 40 else "40-59"
        fname  = "MyGP_accessLog_%s_%s_%s.log" % (
            dt.strftime("%y%m%d%H"), window, source_ip_dashed
        )
        filepath = os.path.join(host_dir, fname)
        file_batches.setdefault(filepath, []).append(line)

    files_written = {}  # type: Dict[str, int]
    saved = 0
    for filepath, batch in file_batches.items():
        try:
            with open(filepath, "a") as f:
                f.write("\n".join(batch) + "\n")
            files_written[filepath] = len(batch)
            saved += len(batch)
        except Exception as e:
            logging.error("Write error %s: %s", filepath, e)

    try:
        _record_analytics(lines, source_ip, receipt_dt, files_written)
    except Exception as e:
        logging.error("Analytics error (non-fatal): %s", e)

    logging.info(
        "%d lines → %s/ ip=%s unparsed=%d meta_lines=%s offsets=%s-%s",
        saved, hostname, source_ip, unparsed,
        meta.get('lines'), meta.get('start_offset'), meta.get('end_offset')
    )
    return "OK - %d lines" % saved, 200


# ── /stats ────────────────────────────────────────────────────────────────────

@app.route('/stats')
def stats():
    hours_back = int(request.args.get("hours", 48))
    days_back  = int(request.args.get("days",  7))
    # Build the cutoff strings in Python to avoid conflict between
    # Python's % string formatting and SQLite's strftime % directives.
    from datetime import timedelta
    hour_cutoff = (datetime.now(UTC) - timedelta(hours=hours_back)).strftime("%Y-%m-%d %H")
    day_cutoff  = (datetime.now(UTC) - timedelta(days=days_back)).strftime("%Y-%m-%d")
    try:
        conn = _get_db()
        hourly_rows = conn.execute(
            "SELECT date_hour,server_ip,line_count,file_count,unique_msisdns"
            " FROM hourly_stats"
            " WHERE date_hour >= ?"
            " ORDER BY date_hour,server_ip",
            (hour_cutoff,)
        ).fetchall()
        daily_rows = conn.execute(
            "SELECT date,server_ip,line_count,unique_msisdns AS unique_msisdns_daily"
            " FROM daily_stats"
            " WHERE date >= ?"
            " ORDER BY date,server_ip",
            (day_cutoff,)
        ).fetchall()
        hourly_totals = conn.execute(
            "SELECT date_hour,"
            " SUM(line_count) AS total_lines,"
            " SUM(file_count) AS total_files,"
            " COUNT(DISTINCT server_ip) AS server_count,"
            " SUM(unique_msisdns) AS unique_msisdns"
            " FROM hourly_stats"
            " WHERE date_hour >= ?"
            " GROUP BY date_hour ORDER BY date_hour",
            (hour_cutoff,)
        ).fetchall()
        daily_totals = conn.execute(
            "SELECT date,"
            " SUM(line_count) AS total_lines,"
            " COUNT(DISTINCT server_ip) AS server_count,"
            " SUM(unique_msisdns) AS unique_msisdns"
            " FROM daily_stats"
            " WHERE date >= ?"
            " GROUP BY date ORDER BY date",
            (day_cutoff,)
        ).fetchall()
        conn.close()
        return jsonify({
            "generated_at":     datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "hourly_by_server": [dict(r) for r in hourly_rows],
            "daily_by_server":  [dict(r) for r in daily_rows],
            "hourly_totals":    [dict(r) for r in hourly_totals],
            "daily_totals":     [dict(r) for r in daily_totals],
        })
    except Exception as e:
        logging.error("/stats error: %s", e)
        return jsonify({"error": str(e)}), 500


# ── /stats/storage ────────────────────────────────────────────────────────────

@app.route('/stats/storage')
def storage_health():
    db_size_mb = os.path.getsize(DB_PATH) / 1e6 if os.path.exists(DB_PATH) else 0
    mem = _mem_stats()
    try:
        conn = _get_db()
        h_cnt  = conn.execute("SELECT COUNT(*) FROM hourly_stats").fetchone()[0]
        d_cnt  = conn.execute("SELECT COUNT(*) FROM daily_stats").fetchone()[0]
        f_cnt  = conn.execute("SELECT COUNT(*) FROM files_seen").fetchone()[0]
        last_c = conn.execute(
            "SELECT value FROM db_meta WHERE key='last_cleanup'"
        ).fetchone()
        last_c = last_c[0] if last_c else "never"
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "db": {
            "path":              DB_PATH,
            "size_mb":           round(db_size_mb, 2),
            "hourly_rows":       h_cnt,
            "daily_rows":        d_cnt,
            "files_seen_rows":   f_cnt,
            "last_cleanup":      last_c,
        },
        "ram": dict(
            list(mem.items()) + [
                ("hour_window_cfg", MSISDN_HOUR_WINDOW),
                ("day_window_cfg",  MSISDN_DAY_WINDOW),
            ]
        ),
        "design_note": (
            "MSISDNs are never written to disk. "
            "In-memory sets dedup within rolling window; "
            "only integer counts are persisted to SQLite. "
            "DB stays under ~70 MB for 5 years at current scale."
        )
    })


# ── /dashboard ────────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyGP Log Analytics</title>
<script>
// ── SVGChart — pure SVG charts with universal hover ──────────────────────────
var SVGChart=(function(){
  var NS='http://www.w3.org/2000/svg';
  function el(tag,attrs,txt){
    var e=document.createElementNS(NS,tag);
    for(var k in attrs) e.setAttribute(k,attrs[k]);
    if(txt!=null) e.textContent=txt;
    return e;
  }
  function fmt(n){
    if(n==null||n===''||n===undefined)return'—';
    if(n===0)return'0';
    if(n>=1e6)return(n/1e6).toFixed(2).replace(/\.?0+$/,'')+'M';
    if(n>=1e3)return(n/1e3).toFixed(1).replace(/\.0$/,'')+'K';
    return Math.round(n)+'';
  }
  function nice(maxV){
    if(!maxV||maxV<=0)return{hi:10,step:2,ticks:5};
    var bases=[1,2,2.5,5,10],mag=Math.pow(10,Math.floor(Math.log10(maxV*1.1)));
    for(var i=0;i<bases.length;i++){
      var s=bases[i]*mag;
      if(s*5>=maxV*1.1)return{hi:s*5,step:s,ticks:5};
      if(s*4>=maxV*1.1)return{hi:s*4,step:s,ticks:4};
    }
    return{hi:maxV*1.2,step:maxV*1.2/5,ticks:5};
  }
  function mount(containerId,svgH){
    var wrap=document.getElementById(containerId);
    if(!wrap)return null;
    var old=wrap.querySelector('svg.mc');
    if(old)wrap.removeChild(old);
    var svg=el('svg',{'class':'mc',width:'100%',height:svgH,
      viewBox:'0 0 1000 '+svgH,preserveAspectRatio:'none',
      style:'display:block;overflow:visible'});
    wrap.appendChild(svg);
    return svg;
  }
  // Shared tooltip div — one per page, reused by all charts
  var _tip=null;
  function getTip(){
    if(!_tip){
      _tip=document.createElement('div');
      _tip.style.cssText='position:fixed;display:none;background:#0d1117;'
        +'border:1px solid #30363d;color:#e6edf3;font-family:monospace;font-size:12px;'
        +'padding:8px 12px;border-radius:6px;pointer-events:none;z-index:9999;'
        +'white-space:nowrap;box-shadow:0 4px 16px #000a;line-height:1.7';
      document.body.appendChild(_tip);
    }
    return _tip;
  }
  function positionTip(e){
    var tip=getTip();
    var tw=tip.offsetWidth||180, th=tip.offsetHeight||60;
    var vw=window.innerWidth, vh=window.innerHeight;
    var x=e.clientX+16, y=e.clientY-th/2;
    if(x+tw>vw-8) x=e.clientX-tw-16;
    if(y<8) y=8;
    if(y+th>vh-8) y=vh-th-8;
    tip.style.left=x+'px'; tip.style.top=y+'px';
  }
  var P={t:40,r:16,b:32,l:70};
  var VW=1000;

  function drawGrid(svg,sc,h){
    var cw=VW-P.l-P.r, ch=h-P.t-P.b;
    svg.appendChild(el('line',{x1:P.l,y1:P.t,x2:P.l,y2:P.t+ch,stroke:'#30363d','stroke-width':1}));
    for(var t=0;t<=sc.ticks;t++){
      var v=t*(sc.hi/sc.ticks);
      var gy=Math.round(P.t+ch-ch*(v/sc.hi));
      svg.appendChild(el('line',{x1:P.l,y1:gy,x2:P.l+cw,y2:gy,stroke:'#21262d','stroke-width':1}));
      svg.appendChild(el('text',{x:P.l-6,y:gy+4,fill:'#6e7681','font-size':11,'text-anchor':'end','font-family':'monospace'},fmt(v)));
    }
    return{cw:cw,ch:ch};
  }
  function drawXlabels(svg,labels,cw,ch,h,offset){
    var step=Math.max(1,Math.ceil(labels.length/14));
    for(var i=0;i<labels.length;i+=step){
      var gx=P.l+(i/(Math.max(labels.length-1,1)))*cw+(offset||0);
      svg.appendChild(el('text',{x:gx,y:h-4,fill:'#6e7681','font-size':10,'text-anchor':'middle','font-family':'monospace'},labels[i]));
    }
  }
  function drawLegend(svg,datasets,W){
    if(datasets.length<2)return;
    var lx=P.l,ly=18;
    datasets.forEach(function(ds){
      svg.appendChild(el('rect',{x:lx,y:ly-9,width:18,height:4,fill:ds.color||'#58a6ff'}));
      var t=el('text',{x:lx+22,y:ly,fill:'#8b949e','font-size':11,'font-family':'monospace'},ds.label||'');
      svg.appendChild(t);
      lx+=22+(ds.label||'').length*7+16;
      if(lx>W-120){lx=P.l;ly+=16;}
    });
  }

  // ── Attach scan-line hover to a line chart ────────────────────────────────
  // Uses an invisible full-width overlay rect to capture mouse movement,
  // then snaps to nearest data column and shows all series values.
  function attachLineHover(wrap,svg,labels,datasets,sc,cw,ch,fmtFn){
    var tip=getTip();
    // Vertical crosshair line
    var vline=el('line',{x1:0,y1:P.t,x2:0,y2:P.t+ch,
      stroke:'#58a6ff55','stroke-width':1,'stroke-dasharray':'4 3',
      opacity:0,style:'pointer-events:none'});
    svg.appendChild(vline);
    // Hover dots — one per dataset
    var hdots=datasets.map(function(ds){
      var c=el('circle',{cx:0,cy:0,r:5,fill:ds.color||'#58a6ff',
        stroke:'#e6edf3','stroke-width':2,opacity:0,style:'pointer-events:none'});
      svg.appendChild(c);
      return c;
    });
    // Full overlay rect for mouse capture
    var overlay=el('rect',{x:P.l,y:P.t,width:cw,height:ch,
      fill:'transparent',style:'cursor:crosshair'});
    svg.appendChild(overlay);

    var svgW=1000; // viewBox width
    function onMove(e){
      var rect=svg.getBoundingClientRect();
      // Map screen pixels → viewBox units
      var scaleX=svgW/rect.width;
      var mx=(e.clientX-rect.left)*scaleX;
      var relX=mx-P.l;
      // Snap to nearest label index
      var idx=Math.round(relX/cw*(labels.length-1));
      idx=Math.max(0,Math.min(labels.length-1,idx));
      var gx=P.l+(idx/(Math.max(labels.length-1,1)))*cw;
      // Show crosshair
      vline.setAttribute('x1',gx); vline.setAttribute('x2',gx);
      vline.setAttribute('opacity',1);
      // Move dots
      var anyVal=false;
      datasets.forEach(function(ds,di){
        var v=(ds.data&&ds.data[idx]);
        if(v==null){hdots[di].setAttribute('opacity',0);return;}
        anyVal=true;
        var cy=P.t+ch-Math.min((v/sc.hi)*ch,ch);
        hdots[di].setAttribute('cx',gx);
        hdots[di].setAttribute('cy',cy);
        hdots[di].setAttribute('opacity',1);
      });
      if(!anyVal){tip.style.display='none';return;}
      // Build tooltip HTML
      var label=labels[idx]||'';
      var html='<div style="color:#8b949e;font-size:11px;margin-bottom:4px">'+label+'</div>';
      datasets.forEach(function(ds){
        var v=(ds.data&&ds.data[idx]);
        if(v==null)return;
        var valStr=fmtFn?fmtFn(v):fmt(v);
        html+='<div><span style="color:'+( ds.color||'#58a6ff')+'">\u25cf</span> '
          +(ds.label?'<span style="color:#8b949e">'+ds.label+'</span> ':'')
          +'<b style="color:'+(ds.color||'#58a6ff')+';font-size:13px">'+valStr+'</b></div>';
      });
      tip.innerHTML=html;
      tip.style.display='block';
      positionTip(e);
    }
    function onLeave(){
      vline.setAttribute('opacity',0);
      hdots.forEach(function(d){d.setAttribute('opacity',0);});
      tip.style.display='none';
    }
    overlay.addEventListener('mousemove',onMove);
    overlay.addEventListener('mouseleave',onLeave);
    // Also hide when mouse leaves the whole chart wrapper
    wrap.addEventListener('mouseleave',onLeave);
  }

  // ── Attach bar hover ──────────────────────────────────────────────────────
  function attachBarHover(wrap,svg,labels,datasets,sc,cw,ch,slot,boff,bw,stacked){
    var tip=getTip();
    labels.forEach(function(lbl,i){
      // Invisible tall hit rect spanning full slot
      var hx=P.l+i*slot;
      var hit=el('rect',{x:Math.round(hx),y:P.t,
        width:Math.round(slot),height:ch,
        fill:'transparent',style:'cursor:default'});
      svg.appendChild(hit);
      hit.addEventListener('mouseenter',function(e){
        var html='<div style="color:#8b949e;font-size:11px;margin-bottom:4px">'+lbl+'</div>';
        if(stacked){
          var total=0;
          datasets.forEach(function(ds){
            var v=(ds.data&&ds.data[i])||0;
            total+=v;
            html+='<div><span style="color:'+(ds.color||'#58a6ff')+'">\u25cf</span> '
              +(ds.label?'<span style="color:#8b949e">'+ds.label+'</span> ':'')
              +'<b style="color:'+(ds.color||'#58a6ff')+'">'+fmt(v)+'</b></div>';
          });
          if(datasets.length>1)
            html+='<div style="border-top:1px solid #30363d;margin-top:4px;padding-top:4px;color:#e6edf3">Total: <b>'+fmt(total)+'</b></div>';
        } else {
          datasets.forEach(function(ds){
            var v=(ds.data&&ds.data[i]);
            if(v==null)return;
            var col=Array.isArray(ds.colors)?ds.colors[i]:(ds.color||'#58a6ff');
            html+='<div><span style="color:'+col+'">\u25cf</span> '
              +(ds.label?'<span style="color:#8b949e">'+ds.label+'</span> ':'')
              +'<b style="color:'+col+';font-size:13px">'+fmt(v)+'</b></div>';
          });
        }
        tip.innerHTML=html;
        tip.style.display='block';
        positionTip(e);
      });
      hit.addEventListener('mousemove',function(e){ positionTip(e); });
      hit.addEventListener('mouseleave',function(){ tip.style.display='none'; });
    });
  }

  return{
    line:function(containerId,labels,datasets,svgH,fmtFn){
      svgH=svgH||200;
      if(!labels||!labels.length)return;
      var allV=[].concat.apply([],datasets.map(function(d){
        return(d.data||[]).filter(function(v){return v!=null;});
      }));
      var maxV=Math.max.apply(null,allV.concat([1]));
      var sc=nice(maxV);
      var svg=mount(containerId,svgH);
      if(!svg)return;
      var g=drawGrid(svg,sc,svgH);
      var cw=g.cw,ch=g.ch;
      var wrap=document.getElementById(containerId);
      drawXlabels(svg,labels,cw,ch,svgH,0);
      drawLegend(svg,datasets,VW);
      datasets.forEach(function(ds){
        var data=ds.data||[];
        var col=ds.color||'#58a6ff';
        var pts=[];
        data.forEach(function(v,i){
          if(v==null)return;
          pts.push({x:P.l+(i/(Math.max(labels.length-1,1)))*cw,
            y:P.t+ch-Math.min((v/sc.hi)*ch,ch),i:i});
        });
        if(!pts.length)return;
        if(ds.fill&&pts.length>1){
          var d2='M'+pts[0].x+','+(P.t+ch);
          pts.forEach(function(p){d2+=' L'+p.x+','+p.y;});
          d2+=' L'+pts[pts.length-1].x+','+(P.t+ch)+' Z';
          svg.appendChild(el('path',{d:d2,fill:col,opacity:0.12}));
        }
        var d='M'+pts[0].x+','+pts[0].y;
        pts.slice(1).forEach(function(p){d+=' L'+p.x+','+p.y;});
        var la={d:d,fill:'none',stroke:col,'stroke-width':2};
        if(ds.dashed)la['stroke-dasharray']='6 3';
        svg.appendChild(el('path',la));
        pts.forEach(function(p){
          var big=ds.highlight&&ds.highlight[p.i];
          svg.appendChild(el('circle',{cx:p.x,cy:p.y,r:big?5:2.5,fill:col}));
          if(big) svg.appendChild(el('circle',{cx:p.x,cy:p.y,r:5,fill:'none',stroke:'#e6edf3','stroke-width':1.5}));
        });
      });
      attachLineHover(wrap,svg,labels,datasets,sc,cw,ch,fmtFn);
    },

    bar:function(containerId,labels,datasets,opts,svgH){
      svgH=svgH||200;
      if(!labels||!labels.length)return;
      var stacked=opts&&opts.stacked;
      var totals=labels.map(function(_,i){
        return datasets.reduce(function(s,d){return s+((d.data&&d.data[i])||0);},0);
      });
      var maxV=Math.max.apply(null,totals.concat([1]));
      var sc=nice(maxV);
      var svg=mount(containerId,svgH);
      if(!svg)return;
      var g=drawGrid(svg,sc,svgH);
      var cw=g.cw,ch=g.ch;
      var wrap=document.getElementById(containerId);
      var slot=cw/labels.length;
      var bw=Math.max(2,slot*0.72);
      var boff=(slot-bw)/2;
      drawXlabels(svg,labels,cw,ch,svgH,slot/2);
      drawLegend(svg,datasets,VW);
      labels.forEach(function(_,i){
        var base=P.t+ch;
        datasets.forEach(function(ds){
          var v=(ds.data&&ds.data[i]);
          if(v==null||v<=0)return;
          var bh=Math.max(1,Math.min((v/sc.hi)*ch,ch));
          var gx=P.l+i*slot+boff;
          var col=Array.isArray(ds.colors)?ds.colors[i]:(ds.color||'#58a6ff');
          svg.appendChild(el('rect',{x:Math.round(gx),y:Math.round(base-bh),
            width:Math.round(bw),height:Math.round(bh),fill:col}));
          if(stacked)base-=bh;
        });
      });
      attachBarHover(wrap,svg,labels,datasets,sc,cw,ch,slot,boff,bw,stacked);
    },

    // Kept for backward compat — now just calls line() which has hover built-in
    lineWithHover:function(containerId,labels,datasets,svgH,fmtFn){
      this.line(containerId,labels,datasets,svgH,fmtFn);
    }
  };
})();
var MicroChart=SVGChart;
</script>
<style>
:root{
  --bg:#0d1117;--panel:#161b22;--border:#30363d;--muted:#8b949e;--text:#e6edf3;
  --green:#3fb950;--red:#f85149;--blue:#58a6ff;--purple:#bc8cff;--orange:#ffa657;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;padding:20px}
a,button{font-family:inherit}

/* ── header ── */
.header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:18px}
.header h1{font-size:18px;font-weight:700}
.header .sub{font-size:11px;color:var(--muted);margin-top:2px}
.hright{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.pill{background:#3fb95015;border:1px solid #3fb95033;border-radius:6px;padding:4px 12px;font-size:11px;color:var(--green)}
.refreshbtn{background:#58a6ff1a;color:var(--blue);border:1px solid #58a6ff44;padding:5px 14px;border-radius:5px;cursor:pointer;font-size:12px}
.refreshbtn:hover{background:#58a6ff33}
#ts{color:var(--muted);font-size:11px}

/* ── day selector ── */
.daybar{display:flex;align-items:center;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.daybar label{font-size:11px;color:var(--muted);margin-right:4px}
.daybtn{background:var(--panel);border:1px solid var(--border);color:var(--muted);padding:5px 16px;
  border-radius:5px;cursor:pointer;font-size:12px;transition:all .15s}
.daybtn.active{background:#58a6ff1a;border-color:var(--blue);color:var(--blue);font-weight:700}
.daybtn:hover:not(.active){border-color:var(--muted);color:var(--text)}
#customDate{background:var(--panel);border:1px solid var(--border);color:var(--text);
  padding:4px 10px;border-radius:5px;font-size:12px;font-family:inherit;cursor:pointer}
#customDate:focus{outline:none;border-color:var(--blue)}

/* ── KPI cards ── */
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px;position:relative}
.card .clabel{font-size:9px;color:var(--muted);margin-bottom:5px;text-transform:uppercase;letter-spacing:.6px}
.card .cval{font-size:22px;font-weight:700;line-height:1}
.card .csub{font-size:10px;color:var(--muted);margin-top:4px}
.card.dim{opacity:.45}

/* ── hour grid ── */
.hourbar-wrap{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:16px}
.hourbar-title{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;display:flex;align-items:center;gap:10px}
.hourbar-title span{color:var(--text);font-size:11px}
.hourbar{display:grid;grid-template-columns:repeat(12,1fr);gap:5px}
@media(max-width:700px){.hourbar{grid-template-columns:repeat(6,1fr)}}
.hpill{background:#1c2128;border:1px dashed #30363d;border-radius:6px;padding:6px 4px;
  text-align:center;cursor:pointer;transition:all .15s}
.hpill:hover:not(.empty){border-color:#8b949e;border-style:solid}
.hpill.active{background:#58a6ff22;border:1px solid #58a6ff}
.hpill.active .hlabel,.hpill.active .hval{color:#58a6ff}
.hpill.now{border:1px solid #ffa65799;background:#ffa65712}
.hpill.now .hlabel,.hpill.now .hval{color:#ffa657}
.hpill.has-data{border-style:solid;border-color:#30363d;background:#1c2128}
.hpill.empty{cursor:default}
.hpill.empty .hlabel{color:#484f58}
.hpill.empty .hval{color:#30363d}
.hlabel{font-size:10px;font-weight:700;display:block;color:#8b949e}
.hval{font-size:9px;color:#6e7681;display:block;margin-top:2px}

/* ── tabs ── */
.tabs{display:flex;border-bottom:1px solid var(--border);margin-bottom:16px;flex-wrap:wrap;gap:2px}
.tab{background:transparent;border:none;border-bottom:2px solid transparent;color:var(--muted);
  padding:8px 16px;cursor:pointer;font-size:12px;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--text);border-bottom-color:var(--blue)}
.sec{display:none}.sec.active{display:block}

/* ── panels ── */
.cw{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:14px}
.cw h2{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.cw h2 .htag{background:#58a6ff1a;border:1px solid #58a6ff44;color:var(--blue);border-radius:4px;padding:1px 7px;font-size:10px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.g2{grid-template-columns:1fr}}

/* ── tables ── */
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:7px 10px;color:var(--muted);border-bottom:1px solid var(--border);font-size:10px;text-transform:uppercase;letter-spacing:.3px}
td{padding:7px 10px;border-bottom:1px solid #ffffff06}
tr:last-child td{border-bottom:none}
tr:hover td{background:#ffffff05}
.num{text-align:right;font-variant-numeric:tabular-nums}

/* ── badges ── */
.badge{display:inline-block;padding:1px 8px;border-radius:4px;font-size:10px;font-weight:700}
.up{color:var(--green);background:#3fb95022}
.dn{color:var(--red);background:#f8514922}
.na{color:var(--muted);background:#ffffff0a}

/* ── chart options ── */
.no-data{display:flex;align-items:center;justify-content:center;height:80px;color:var(--muted);font-size:12px}

/* ── storage ── */
.stor-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.stor-grid{grid-template-columns:1fr}}
.stor-item{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid #ffffff06;font-size:12px}
.stor-item:last-child{border-bottom:none}
.stor-key{color:var(--muted)}
.stor-val{font-weight:700}
</style>
</head>
<body>

<!-- ── Header ── -->
<div class="header">
  <div>
    <h1>📊 MyGP Log Analytics</h1>
    <div class="sub">Metrics from SQLite · MSISDNs never written to disk · auto-refresh 60s</div>
  </div>
  <div class="hright">
    <span id="ts">Loading…</span>
    <span class="pill" id="dbpill">DB — MB · RAM — MB</span>
    <button class="refreshbtn" onclick="loadAll()">⟳ Refresh</button>
  </div>
</div>

<!-- ── Day selector ── -->
<div class="daybar">
  <label>Viewing:</label>
  <button class="daybtn" id="btnYes" onclick="setDay('yesterday')">◀ Yesterday</button>
  <button class="daybtn active" id="btnTod" onclick="setDay('today')">Today</button>
  <button class="daybtn" id="btnCus" onclick="setDay('custom')">Custom</button>
  <input type="date" id="customDate" style="display:none" onchange="setDay('custom')" />
  <span id="selDayLabel" style="color:var(--muted);font-size:11px"></span>
</div>

<!-- ── KPI row ── -->
<div class="kpis" id="kpis"></div>

<!-- ── Hour grid ── -->
<div class="hourbar-wrap">
  <div class="hourbar-title">
    Hours — click any hour to drill down &nbsp;|&nbsp;
    <span id="hourSelLabel">No hour selected — showing full day</span>
    <button class="refreshbtn" id="clearHour" onclick="clearHour()" style="padding:2px 10px;font-size:11px;display:none">✕ Clear</button>
  </div>
  <div class="hourbar" id="hourbar"></div>
  <div id="noDataBanner" style="display:none;align-items:center;gap:14px;padding:18px;margin-top:10px;
    background:#ffa65710;border:1px dashed #ffa65766;border-radius:8px;font-size:12px;color:#ffa657">
    <span style="font-size:22px;flex-shrink:0">⏳</span>
    <div>
      <strong style="font-size:13px">No data yet for <span id="noDataDay"></span></strong><br>
      <span style="color:#8b949e;line-height:1.8">
        The receiver is running but no batches have been recorded for this day yet.<br>
        Shippers send every ~30 seconds. Confirm they are running and pointing to this receiver:<br>
        <code style="background:#0d111799;padding:2px 8px;border-radius:3px;color:#58a6ff;font-size:11px">
          grep "lines →" /app/log/access-log-terminal/stats.log | tail -5
        </code>
      </span>
    </div>
  </div>
</div>

<!-- ── Tabs ── -->
<div class="tabs">
  <button class="tab active" onclick="sw('overview',this)">Overview</button>
  <button class="tab" onclick="sw('byserver',this)">By Server</button>
  <button class="tab" onclick="sw('compare',this)">Yesterday vs Today</button>
  <button class="tab" onclick="sw('haudau',this)">HAU &amp; DAU</button>
  <button class="tab" onclick="sw('daily',this)">Daily Summary</button>
  <button class="tab" onclick="sw('storage',this)">Storage Health</button>
</div>

<!-- ── Overview tab ── -->
<div id="overview" class="sec active">
  <div class="cw">
    <h2>Log Lines per Hour <span class="htag" id="lbl_lines"></span></h2>
    <div id="cLines" style="min-height:200px"></div>
  </div>
  <div class="cw">
    <h2>Unique MSISDNs per Hour <span class="htag" id="lbl_msisdn"></span></h2>
    <div id="cMsisdn" style="min-height:200px"></div>
  </div>
  <div class="g2">
    <div class="cw">
      <h2>Active Servers per Hour <span class="htag" id="lbl_srv"></span></h2>
      <div id="cSrv" style="min-height:180px"></div>
    </div>
    <div class="cw">
      <h2>Files Created per Hour <span class="htag" id="lbl_files"></span></h2>
      <div id="cFiles" style="min-height:180px"></div>
    </div>
  </div>
</div>

<!-- ── HAU / DAU tab ── -->
<div id="haudau" class="sec">
  <div class="g2">
    <div class="cw">
      <h2>HAU &mdash; Hourly Active Users <span class="htag" id="lbl_hau"></span></h2>
      <div style="color:var(--muted);font-size:11px;margin-bottom:6px">Unique MSISDNs per hour &mdash; hover anywhere on chart for exact count</div>
      <div id="cHAU" style="min-height:220px;position:relative"></div>
    </div>
    <div class="cw">
      <h2>DAU &mdash; Daily Active Users <span class="htag" id="lbl_dau"></span></h2>
      <div style="color:var(--muted);font-size:11px;margin-bottom:6px">Unique MSISDNs per day &mdash; hover anywhere on chart for exact count</div>
      <div id="cDAU" style="min-height:220px;position:relative"></div>
    </div>
  </div>
  <div class="g2">
    <div class="cw">
      <h2>HAU Peak &amp; Average</h2>
      <div id="hauStats" style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px"></div>
    </div>
    <div class="cw">
      <h2>DAU Trend</h2>
      <div id="dauStats" style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px"></div>
    </div>
  </div>
</div>

<!-- ── By Server tab ── -->
<div id="byserver" class="sec">
  <div class="cw">
    <h2>Lines per Hour by Server <span class="htag" id="lbl_bsChart"></span></h2>
    <div id="cByServer" style="min-height:240px"></div>
  </div>
  <div class="cw">
    <h2>Per-Server Breakdown <span class="htag" id="lbl_bsTbl"></span></h2>
    <table>
      <thead><tr><th>#</th><th>Server IP</th><th class="num">Lines</th><th class="num">Files</th><th class="num">Unique MSISDNs</th></tr></thead>
      <tbody id="svrtbl"></tbody>
    </table>
  </div>
</div>

<!-- ── Compare tab ── -->
<div id="compare" class="sec">
  <div class="cw">
    <h2>Log Lines per Hour — Today vs Yesterday</h2>
    <div id="cCmpLines" style="min-height:220px"></div>
  </div>
  <div class="cw">
    <h2>Unique MSISDNs per Hour — Today vs Yesterday</h2>
    <div id="cCmpMsisdn" style="min-height:220px"></div>
  </div>
  <div class="cw">
    <h2>Daily Summary Comparison</h2>
    <table>
      <thead><tr><th>Metric</th><th class="num">Yesterday</th><th class="num">Today (so far)</th><th class="num">Change</th></tr></thead>
      <tbody id="cmptbl"></tbody>
    </table>
    <div style="font-size:10px;color:var(--muted);margin-top:10px">
      * Today values are partial until midnight. % change compares full day vs partial day.
    </div>
  </div>
</div>

<!-- ── Daily Summary tab ── -->
<div id="daily" class="sec">
  <div class="cw">
    <h2>All Days in DB</h2>
    <table>
      <thead><tr><th>Date</th><th class="num">Total Lines</th><th class="num">Active Servers</th><th class="num">Unique MSISDNs</th></tr></thead>
      <tbody id="daytbl"></tbody>
    </table>
  </div>
  <div class="cw">
    <h2>Per-Server Daily Breakdown</h2>
    <table>
      <thead><tr><th>Date</th><th>Server</th><th class="num">Lines</th><th class="num">Unique MSISDNs</th></tr></thead>
      <tbody id="daysvrtbl"></tbody>
    </table>
  </div>
</div>

<!-- ── Storage tab ── -->
<div id="storage" class="sec">
  <div class="stor-grid">
    <div class="cw">
      <h2>Database</h2>
      <div id="storDB"></div>
    </div>
    <div class="cw">
      <h2>RAM (MSISDN sets)</h2>
      <div id="storRAM"></div>
    </div>
  </div>
  </div>
</div>

<script>
// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────
var DATA    = { hourly_totals:[], hourly_by_server:[], daily_totals:[], daily_by_server:[] };
var STORAGE = {};
var selDay  = 'today';   // 'today' | 'yesterday' | 'YYYY-MM-DD'
var selHour = null;      // null | '14' | '08' etc (zero-padded string)

var PAL = ['#58a6ff','#3fb950','#ffa657','#bc8cff','#f85149','#56d364','#d29922','#79c0ff',
           '#ffb77a','#e06c75','#61afef','#98c379','#c678dd','#56b6c2','#d19a66','#abb2bf'];
function fmt(n){
  if(n==null||n===undefined) return '—';
  if(n>=1e6) return (n/1e6).toFixed(2)+'M';
  if(n>=1e3) return (n/1e3).toFixed(1)+'K';
  return Number(n).toLocaleString();
}
function badge(t,y){
  if(!t&&!y) return '<span class="badge na">N/A</span>';
  if(!y)     return '<span class="badge na">NEW</span>';
  var p=((t-y)/y*100).toFixed(1);
  return '<span class="badge '+(p>=0?'up':'dn')+'">'+(p>=0?'+':'')+p+'%</span>';
}
function _localDateStr(d){
  // Format date as YYYY-MM-DD using LOCAL time (not UTC)
  // Critical: UTC would give wrong date for +0600 timezone after midnight UTC
  var y=d.getFullYear();
  var m=('0'+(d.getMonth()+1)).slice(-2);
  var day=('0'+d.getDate()).slice(-2);
  return y+'-'+m+'-'+day;
}
function todayStr(){
  return _localDateStr(new Date());
}
function yesterdayStr(){
  var d=new Date(); d.setDate(d.getDate()-1);
  return _localDateStr(d);
}
function activeDayStr(){
  if(selDay==='today')     return todayStr();
  if(selDay==='yesterday') return yesterdayStr();
  return selDay;
}
function nowHour(){
  // LOCAL hour zero-padded — matches DB date_hour format (server stores local time)
  return ('0'+new Date().getHours()).slice(-2);
}
function sw(id,el){
  document.querySelectorAll('.sec').forEach(function(s){s.classList.toggle('active',s.id===id);});
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});
  el.classList.add('active');
  renderActive();
}

// ─────────────────────────────────────────────────────────────────────────────
// Day / hour selection
// ─────────────────────────────────────────────────────────────────────────────
function setDay(d){
  if(d==='custom'){
    var inp=document.getElementById('customDate');
    inp.style.display='inline-block';
    var v=inp.value;
    if(!v){ inp.focus(); return; }
    selDay=v;
  } else {
    document.getElementById('customDate').style.display='none';
    selDay=d;
  }
  selHour=null;
  ['btnYes','btnTod','btnCus'].forEach(function(id){ document.getElementById(id).classList.remove('active'); });
  if(d==='yesterday') document.getElementById('btnYes').classList.add('active');
  else if(d==='today') document.getElementById('btnTod').classList.add('active');
  else document.getElementById('btnCus').classList.add('active');
  render();
}
function selectHour(h){
  selHour = (selHour===h) ? null : h;
  render();
}
function clearHour(){
  selHour=null;
  render();
}

// ─────────────────────────────────────────────────────────────────────────────
// Data helpers
// ─────────────────────────────────────────────────────────────────────────────
function hourlyForDay(){
  var day=activeDayStr();
  return DATA.hourly_totals.filter(function(r){ return r.date_hour.startsWith(day); })
             .sort(function(a,b){ return a.date_hour<b.date_hour?-1:1; });
}
function serverForHour(dh){
  // dh = full 'YYYY-MM-DD HH' string
  return DATA.hourly_by_server.filter(function(r){ return r.date_hour===dh; })
             .sort(function(a,b){ return b.line_count-a.line_count; });
}
function serverForDay(){
  var day=activeDayStr();
  return DATA.hourly_by_server.filter(function(r){ return r.date_hour.startsWith(day); });
}
function activeHourStr(){
  if(!selHour) return null;
  return activeDayStr()+' '+selHour;
}
function kpiSource(){
  // returns { total_lines, unique_msisdns, server_count, total_files, sublabel }
  if(selHour){
    var dh=activeHourStr();
    var hr=DATA.hourly_totals.find(function(r){ return r.date_hour===dh; })||{};
    return {
      total_lines:    hr.total_lines,
      unique_msisdns: hr.unique_msisdns,
      server_count:   hr.server_count,
      total_files:    hr.total_files,
      sublabel: activeDayStr()+' '+selHour+':00–'+selHour+':59'
    };
  }
  // Full day
  var day=activeDayStr();
  var rows=hourlyForDay();
  return {
    total_lines:    rows.reduce(function(s,r){return s+(r.total_lines||0);},0),
    unique_msisdns: (DATA.daily_totals.find(function(r){return r.date===day;})||{}).unique_msisdns,
    server_count:   Math.max.apply(null,rows.map(function(r){return r.server_count||0;}).concat([0])),
    total_files:    rows.reduce(function(s,r){return s+(r.total_files||0);},0),
    sublabel: 'All hours on '+activeDayStr()
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Render
// ─────────────────────────────────────────────────────────────────────────────
function render(){
  document.getElementById('selDayLabel').textContent = activeDayStr();
  var ndd=document.getElementById('noDataDay'); if(ndd) ndd.textContent=activeDayStr();
  renderKPIs();
  renderHourGrid();
  renderActive();
}

function renderKPIs(){
  var s=kpiSource();
  var now=activeDayStr()===todayStr();
  var items=[
    {label:'Lines',          val:s.total_lines,    color:'#58a6ff'},
    {label:'Unique MSISDNs', val:s.unique_msisdns, color:'#3fb950'},
    {label:'Active Servers', val:s.server_count,   color:'#ffa657'},
    {label:'Files Created',  val:s.total_files,    color:'#bc8cff'},
  ];
  document.getElementById('kpis').innerHTML=items.map(function(x){
    return '<div class="card">'
      +'<div class="clabel">'+x.label+'</div>'
      +'<div class="cval" style="color:'+x.color+'">'+fmt(x.val)+'</div>'
      +'<div class="csub">'+s.sublabel+'</div>'
      +'</div>';
  }).join('');
}

function renderHourGrid(){
  var rows=hourlyForDay();
  var byHour={};
  rows.forEach(function(r){ byHour[r.date_hour.slice(11)]=r; });
  var nowH=activeDayStr()===todayStr()?nowHour():null;
  var maxLines=Math.max.apply(null,rows.map(function(r){return r.total_lines||0;}).concat([1]));

  var html='';
  for(var h=0;h<24;h++){
    var hs=('0'+h).slice(-2);
    var row=byHour[hs];
    var isEmpty=!row;
    var isNow=hs===nowH;
    var isSel=hs===selHour;
    // classes: always show pill; add has-data when data exists; now = current hour
    var cls='hpill'
      +(isEmpty?' empty':' has-data')
      +(isNow?' now':'')
      +(isSel&&!isEmpty?' active':'');
    var lines=row?(row.total_lines||0):0;
    // heat tint for pills with data
    var style='';
    if(!isEmpty&&!isNow&&!isSel){
      var intensity=Math.round(20+((lines/maxLines)*60));
      style=' style="border-color:rgba(88,166,255,0.'+intensity+')"';
    }
    html+='<div class="'+cls+'"'+style
      +' onclick="'+(isEmpty?'':'selectHour(\''+hs+'\')')+'">'
      +'<span class="hlabel">'+hs+':00'+(isNow?' ●':'')+'</span>'
      +'<span class="hval">'+(isEmpty?'—':fmt(lines))+'</span>'
      +'</div>';
  }
  document.getElementById('hourbar').innerHTML=html;

  // no-data banner
  var nb=document.getElementById('noDataBanner');
  var nd=document.getElementById('noDataDay');
  if(nd) nd.textContent=activeDayStr();
  if(nb) nb.style.display=(rows.length===0?'flex':'none');

  // Hour sel label
  var lbl=document.getElementById('hourSelLabel');
  var clr=document.getElementById('clearHour');
  if(selHour){
    lbl.textContent='Showing '+selHour+':00 – '+selHour+':59 on '+activeDayStr();
    lbl.style.color='var(--blue)';
    clr.style.display='inline-block';
  } else {
    lbl.textContent='No hour selected — showing full day totals';
    lbl.style.color='var(--muted)';
    clr.style.display='none';
  }
}

function renderActive(){
  // Use rAF so the DOM is painted before we measure canvas widths
  requestAnimationFrame(function(){
    var active=document.querySelector('.sec.active');
    if(!active) return;
    var id=active.id;
    if(id==='overview')  renderOverview();
    if(id==='byserver')  renderByServer();
    if(id==='compare')   renderCompare();
    if(id==='haudau')    renderHAUDAU();
    if(id==='daily')     renderDaily();
    if(id==='storage')   renderStorage();
  });
}

// ── Overview ──────────────────────────────────────────────────────────────────
function renderOverview(){
  try{
  var rows=hourlyForDay();
  // Always use all 24 hours on x-axis — fill 0 for missing hours
  var allHrs=[];
  for(var h=0;h<24;h++) allHrs.push(('0'+h).slice(-2));
  var byHour={};
  rows.forEach(function(r){ byHour[r.date_hour.slice(11)]=r; });
  var labels=allHrs.map(function(h){return h+':00';});

  var tag=selHour?selHour+':00':'all hours';
  ['lbl_lines','lbl_msisdn','lbl_srv','lbl_files'].forEach(function(id){
    var el=document.getElementById(id);
    if(el) el.textContent=activeDayStr()+' · '+tag;
  });

  if(!rows.length){
    ['cLines','cMsisdn','cSrv','cFiles'].forEach(function(id){
      var el=document.getElementById(id);
      if(el) el.innerHTML='<div style="padding:40px;text-align:center;color:#484f58;font-size:12px;font-family:monospace">No data for this period yet</div>';
    });
    return;
  }

  var hl=function(h){ return h===selHour; };
  MicroChart.line('cLines',labels,[{
    data:allHrs.map(function(h){return byHour[h]?byHour[h].total_lines:null;}),
    color:'#58a6ff',fill:true,
    highlight:allHrs.map(hl)
  }]);
  MicroChart.line('cMsisdn',labels,[{
    data:allHrs.map(function(h){return byHour[h]?byHour[h].unique_msisdns:null;}),
    color:'#3fb950',fill:true,
    highlight:allHrs.map(hl)
  }]);
  MicroChart.line('cSrv',labels,[{
    data:allHrs.map(function(h){return byHour[h]?byHour[h].server_count:null;}),
    color:'#ffa657',fill:true
  }]);
  MicroChart.bar('cFiles',labels,[{
    data:allHrs.map(function(h){return byHour[h]?byHour[h].total_files:null;}),
    colors:allHrs.map(function(h){return h===selHour?'#bc8cff':'#bc8cff55';})
  }],{});
  } catch(e){ showErr('renderOverview error: '+e.message+'\n'+e.stack); }
}

// ── By Server ─────────────────────────────────────────────────────────────────
function renderByServer(){
  var dayRows=serverForDay();
  var hourRows=selHour ? serverForHour(activeHourStr()) : serverForHour(
    (hourlyForDay().slice(-1)[0]||{}).date_hour||''
  );
  var dh=selHour ? (activeHourStr()) : ((hourlyForDay().slice(-1)[0]||{}).date_hour||'last');
  var tblLabel=selHour
    ? activeDayStr()+' · '+selHour+':00–'+selHour+':59'
    : activeDayStr()+' · latest hour ('+dh.slice(11)+':00)';

  document.getElementById('lbl_bsChart').textContent=activeDayStr()+' · all hours';
  document.getElementById('lbl_bsTbl').textContent=tblLabel;

  // ALWAYS use all 24 hours on x-axis — never just hours with data
  var hrs=[];
  for(var h=0;h<24;h++) hrs.push(('0'+h).slice(-2)+':00');

  // Build per-server data for all 24 hours
  var srvs=[...new Set(dayRows.map(function(r){return r.server_ip;}))].sort();

  // For cleaner chart: show top 8 servers by total, group rest as "Others"
  var srvTotals={};
  srvs.forEach(function(s){
    srvTotals[s]=dayRows.filter(function(r){return r.server_ip===s;})
      .reduce(function(sum,r){return sum+(r.line_count||0);},0);
  });
  var sortedSrvs=srvs.slice().sort(function(a,b){return srvTotals[b]-srvTotals[a];});
  var topSrvs=sortedSrvs.slice(0,8);
  var otherSrvs=sortedSrvs.slice(8);

  var datasets=topSrvs.map(function(s,i){
    return{
      label:s.replace('10-10-21-','…'),
      color:PAL[i%PAL.length],
      data:hrs.map(function(hl){
        var hh=hl.slice(0,2);
        var row=dayRows.find(function(r){return r.date_hour.slice(11)===hh&&r.server_ip===s;});
        return row?row.line_count:0;
      })
    };
  });

  // Add "Others" bucket if needed
  if(otherSrvs.length>0){
    datasets.push({
      label:'Others('+otherSrvs.length+')',
      color:'#484f58',
      data:hrs.map(function(hl){
        var hh=hl.slice(0,2);
        return otherSrvs.reduce(function(sum,s){
          var row=dayRows.find(function(r){return r.date_hour.slice(11)===hh&&r.server_ip===s;});
          return sum+(row?row.line_count:0);
        },0);
      })
    });
  }

  MicroChart.bar('cByServer', hrs, datasets, {stacked:true}, 260);

  // Table
  document.getElementById('svrtbl').innerHTML=hourRows.map(function(r,i){
    return '<tr>'
      +'<td style="color:var(--muted)">'+(i+1)+'</td>'
      +'<td>'+r.server_ip+'</td>'
      +'<td class="num" style="color:#58a6ff">'+fmt(r.line_count)+'</td>'
      +'<td class="num" style="color:#bc8cff">'+fmt(r.file_count)+'</td>'
      +'<td class="num" style="color:#3fb950">'+fmt(r.unique_msisdns)+'</td>'
      +'</tr>';
  }).join('')||'<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No data for this hour</td></tr>';
}

// ── HAU / DAU ─────────────────────────────────────────────────────────────────
function renderHAUDAU(){
  try{
  var tod=activeDayStr();
  var hourRows=DATA.hourly_totals.filter(function(r){return r.date_hour.startsWith(tod);});

  // HAU: unique MSISDNs per hour for selected day (full 24h axis)
  var allHrs=[]; for(var h=0;h<24;h++) allHrs.push(('0'+h).slice(-2));
  var byHour={};
  hourRows.forEach(function(r){byHour[r.date_hour.slice(11)]=r;});
  var hauLabels=allHrs.map(function(h){return h+':00';});
  var hauData=allHrs.map(function(h){return byHour[h]?byHour[h].unique_msisdns:null;});

  document.getElementById('lbl_hau').textContent=tod;
  SVGChart.lineWithHover('cHAU', hauLabels, [{
    data:hauData, color:'#3fb950', fill:true, label:'Unique MSISDNs'
  }], 240, function(v){ return v>=1e6?(v/1e6).toFixed(2)+'M':v>=1e3?(v/1e3).toFixed(1)+'K':v+''; });

  // HAU stats
  var validHAU=hauData.filter(function(v){return v!=null&&v>0;});
  var peakHAU=validHAU.length?Math.max.apply(null,validHAU):0;
  var avgHAU=validHAU.length?Math.round(validHAU.reduce(function(a,b){return a+b;},0)/validHAU.length):0;
  var peakHr=hauData.indexOf(peakHAU);
  document.getElementById('hauStats').innerHTML=[
    {label:'Peak Hour', val:peakHAU>=1e3?(peakHAU/1e3).toFixed(1)+'K':peakHAU, sub:peakHr>=0?allHrs[peakHr]+':00':'—', color:'#3fb950'},
    {label:'Avg/Hour',  val:avgHAU>=1e3?(avgHAU/1e3).toFixed(1)+'K':avgHAU,  sub:'active hours: '+validHAU.length, color:'#58a6ff'},
    {label:'Total',     val:DATA.daily_totals.filter(function(r){return r.date===tod;})[0]?
      (function(v){return v>=1e6?(v/1e6).toFixed(2)+'M':v>=1e3?(v/1e3).toFixed(1)+'K':v+'';})
      (DATA.daily_totals.filter(function(r){return r.date===tod;})[0].unique_msisdns||0):'0',
      sub:'unique all day', color:'#ffa657'},
  ].map(function(x){
    return '<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 20px;min-width:140px">'
      +'<div style="font-size:10px;color:#8b949e;font-family:monospace;letter-spacing:1px">'+x.label+'</div>'
      +'<div style="font-size:26px;font-weight:700;color:'+x.color+';font-family:monospace">'+x.val+'</div>'
      +'<div style="font-size:10px;color:#6e7681;font-family:monospace">'+x.sub+'</div>'
      +'</div>';
  }).join('');

  // DAU: unique MSISDNs per day across all days in DB
  var days=DATA.daily_totals.slice().sort(function(a,b){return a.date>b.date?1:-1;});
  var dauLabels=days.map(function(d){return d.date.slice(5);}); // MM-DD
  var dauData=days.map(function(d){return d.unique_msisdns||0;});
  document.getElementById('lbl_dau').textContent='All days in DB';
  SVGChart.lineWithHover('cDAU', dauLabels, [{
    data:dauData, color:'#ffa657', fill:true, label:'Daily Unique MSISDNs'
  }], 240, function(v){ return v>=1e6?(v/1e6).toFixed(2)+'M':v>=1e3?(v/1e3).toFixed(1)+'K':v+''; });

  // DAU stats
  var validDAU=dauData.filter(function(v){return v>0;});
  var peakDAU=validDAU.length?Math.max.apply(null,validDAU):0;
  var avgDAU=validDAU.length?Math.round(validDAU.reduce(function(a,b){return a+b;},0)/validDAU.length):0;
  document.getElementById('dauStats').innerHTML=[
    {label:'Peak Day',  val:peakDAU>=1e6?(peakDAU/1e6).toFixed(2)+'M':peakDAU>=1e3?(peakDAU/1e3).toFixed(1)+'K':peakDAU+'', sub:days.length?days[dauData.indexOf(peakDAU)].date:'—', color:'#ffa657'},
    {label:'Avg/Day',   val:avgDAU>=1e6?(avgDAU/1e6).toFixed(2)+'M':avgDAU>=1e3?(avgDAU/1e3).toFixed(1)+'K':avgDAU+'',     sub:validDAU.length+' day(s) with data', color:'#58a6ff'},
    {label:'Days in DB',val:days.length+'', sub:'total tracked days', color:'#3fb950'},
  ].map(function(x){
    return '<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 20px;min-width:140px">'
      +'<div style="font-size:10px;color:#8b949e;font-family:monospace;letter-spacing:1px">'+x.label+'</div>'
      +'<div style="font-size:26px;font-weight:700;color:'+x.color+';font-family:monospace">'+x.val+'</div>'
      +'<div style="font-size:10px;color:#6e7681;font-family:monospace">'+x.sub+'</div>'
      +'</div>';
  }).join('');

  }catch(e){ showErr('renderHAUDAU: '+e.message+'\n'+e.stack); }
}

// ── Compare ───────────────────────────────────────────────────────────────────
function renderCompare(){
  var tod=todayStr(), yes=yesterdayStr();
  var tH=DATA.hourly_totals.filter(function(r){return r.date_hour.startsWith(tod);});
  var yH=DATA.hourly_totals.filter(function(r){return r.date_hour.startsWith(yes);});
  var hrs=[];
  for(var h=0;h<24;h++) hrs.push(('0'+h).slice(-2)+':00');

  function gv(arr,hh,key){
    var f=arr.find(function(r){return r.date_hour.slice(11)+':00'===hh;});
    return f?(f[key]||0):null;
  }

  MicroChart.line('cCmpLines',hrs,[
    {label:'Today ('+tod+')',    data:hrs.map(function(h){return gv(tH,h,'total_lines');}),   color:'#58a6ff'},
    {label:'Yesterday ('+yes+')',data:hrs.map(function(h){return gv(yH,h,'total_lines');}),   color:'#6e7681',dashed:true}
  ]);
  MicroChart.line('cCmpMsisdn',hrs,[
    {label:'Today',    data:hrs.map(function(h){return gv(tH,h,'unique_msisdns');}),color:'#3fb950'},
    {label:'Yesterday',data:hrs.map(function(h){return gv(yH,h,'unique_msisdns');}),color:'#6e7681',dashed:true}
  ]);

  var tT=DATA.daily_totals.find(function(r){return r.date===tod;})||{};
  var yT=DATA.daily_totals.find(function(r){return r.date===yes;})||{};
  document.getElementById('cmptbl').innerHTML=[
    ['Total Lines',    tT.total_lines,    yT.total_lines],
    ['Unique MSISDNs', tT.unique_msisdns, yT.unique_msisdns],
    ['Active Servers', tT.server_count,   yT.server_count],
  ].map(function(x){
    return '<tr>'
      +'<td>'+x[0]+'</td>'
      +'<td class="num" style="color:var(--muted)">'+fmt(x[2])+'</td>'
      +'<td class="num" style="color:#58a6ff;font-weight:700">'+fmt(x[1])+'</td>'
      +'<td class="num">'+badge(x[1],x[2])+'</td>'
      +'</tr>';
  }).join('');
}

// ── Daily ─────────────────────────────────────────────────────────────────────
function renderDaily(){
  document.getElementById('daytbl').innerHTML=DATA.daily_totals.slice().reverse().map(function(r){
    return '<tr>'
      +'<td>'+r.date+'</td>'
      +'<td class="num" style="color:#58a6ff">'+fmt(r.total_lines)+'</td>'
      +'<td class="num" style="color:#ffa657">'+fmt(r.server_count)+'</td>'
      +'<td class="num" style="color:#3fb950">'+fmt(r.unique_msisdns)+'</td>'
      +'</tr>';
  }).join('')||'<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No data yet</td></tr>';

  document.getElementById('daysvrtbl').innerHTML=DATA.daily_by_server.slice().sort(function(a,b){
    return a.date<b.date?1:a.date>b.date?-1:b.line_count-a.line_count;
  }).map(function(r){
    return '<tr>'
      +'<td style="color:var(--muted)">'+r.date+'</td>'
      +'<td>'+r.server_ip+'</td>'
      +'<td class="num" style="color:#58a6ff">'+fmt(r.line_count)+'</td>'
      +'<td class="num" style="color:#3fb950">'+fmt(r.unique_msisdns_daily)+'</td>'
      +'</tr>';
  }).join('');
}

// ── Storage ───────────────────────────────────────────────────────────────────
function renderStorage(){
  var s=STORAGE;
  if(!s.db) { document.getElementById('storDB').innerHTML='<div style="color:var(--muted)">Loading…</div>'; return; }
  function row(k,v){ return '<div class="stor-item"><span class="stor-key">'+k+'</span><span class="stor-val">'+v+'</span></div>'; }
  document.getElementById('storDB').innerHTML=
    row('File path',   '<span style="font-size:10px;color:var(--muted)">'+s.db.path+'</span>')+
    row('Size on disk','<span style="color:var(--green)">'+s.db.size_mb+' MB</span>')+
    row('hourly_stats rows', fmt(s.db.hourly_rows))+
    row('daily_stats rows',  fmt(s.db.daily_rows))+
    row('files_seen rows',   fmt(s.db.files_seen_rows))+
    row('Last cleanup', s.db.last_cleanup||'pending');
  document.getElementById('storRAM').innerHTML=
    row('Hour sets in RAM',  s.ram.hour_sets+' sets')+
    row('MSISDNs in hour sets', fmt(s.ram.hour_msisdns))+
    row('Day sets in RAM',   s.ram.day_sets+' sets')+
    row('MSISDNs in day sets',  fmt(s.ram.day_msisdns))+
    row('Estimated RAM used','<span style="color:var(--orange)">'+s.ram.estimated_ram_mb+' MB</span>')+
    row('Rolloff window',    s.ram.hour_window_cfg+'h hourly / '+s.ram.day_window_cfg+'d daily');
}

// ─────────────────────────────────────────────────────────────────────────────
// Data fetch
// ─────────────────────────────────────────────────────────────────────────────
function showErr(msg){
  var d=document.getElementById('dbgerr');
  if(!d){d=document.createElement('div');d.id='dbgerr';
    d.style.cssText='position:fixed;bottom:0;left:0;right:0;background:#f85149;color:#fff;font-family:monospace;font-size:12px;padding:8px 12px;z-index:9999;white-space:pre-wrap;max-height:40vh;overflow:auto';
    document.body.appendChild(d);}
  d.textContent=msg;
}

async function loadAll(){
  document.getElementById('ts').textContent='Refreshing…';
  try{
    var r1=await fetch('/stats?hours=48&days=7');
    var r2=await fetch('/stats/storage');
    DATA    = await r1.json();
    STORAGE = await r2.json();
    document.getElementById('ts').textContent='Updated: '+new Date().toLocaleTimeString();
    var mb  = STORAGE.db?STORAGE.db.size_mb:'?';
    var ram = STORAGE.ram?STORAGE.ram.estimated_ram_mb:'?';
    document.getElementById('dbpill').textContent='DB '+mb+' MB · RAM '+ram+' MB';
  } catch(e){
    document.getElementById('ts').textContent='Error: '+e.message;
    showErr('loadAll error: '+e.message+'\n'+e.stack);
  }
  try{
    render();
  } catch(e){
    showErr('render() error: '+e.message+'\n'+e.stack);
  }
}

// Resize redraws all visible charts
window.addEventListener('resize', function(){ setTimeout(renderActive,50); });

// ─────────────────────────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────────────────────────
// Set custom date input max to today
document.getElementById('customDate').max=todayStr();
document.getElementById('customDate').value=todayStr();

loadAll();
setInterval(loadAll, 60000);

// SVG self-test: draws a green checkmark line — if you see it, SVG works
(function(){
  var d=document.createElement('div');
  d.style.cssText='position:fixed;top:4px;left:50%;transform:translateX(-50%);z-index:8888;opacity:0.7';
  d.innerHTML='<svg width="120" height="16" style="display:block"><rect width="120" height="16" fill="#0d1117"/>'
    +'<polyline points="4,8 40,8 80,4 120,12" fill="none" stroke="#3fb950" stroke-width="2"/>'
    +'<text x="46" y="12" fill="#3fb950" font-size="9" font-family="monospace">SVG OK</text></svg>';
  document.body.appendChild(d);
  setTimeout(function(){if(d.parentNode)d.parentNode.removeChild(d);},8000);
})();
</script>
</body>
</html>"""


@app.route('/dashboard')
def dashboard():
    return Response(DASHBOARD_HTML, mimetype='text/html')


@app.route('/health')
def health():
    return "OK", 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)