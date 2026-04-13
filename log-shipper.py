import os
import time
import logging
import threading
import requests
import socket
import json
import gzip
import hashlib
from typing import Tuple, Dict, List
from urllib.parse import urlparse
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver as Observer  # Reliable in production
from tenacity import retry, stop_after_attempt, wait_fixed

# CONFIGURATION (env overrides supported)
LOG_FILE = os.getenv("LOG_FILE", "/app/log/nginx/access.log")
OFFSET_FILE = os.getenv("OFFSET_FILE", "/app/log-shipper/latest.offset")
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "10000"))

# Prefer a byte-size cap so a single batch doesn't become enormous.
MAX_BATCH_BYTES = int(os.getenv("MAX_BATCH_BYTES", str(5 * 1024 * 1024)))  # 5MB

SEND_URL = os.getenv("SEND_URL", "http://10.10.23.212:8000/upload")
LOGGING_FILE = os.getenv("LOGGING_FILE", "/app/log-shipper/log_shipper_status.log")

# Poll cadence for the tailer (watchdog just triggers faster wakeups)
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "0.5"))

# Requests timeout (connect, read)
REQUEST_TIMEOUT_SECS = float(os.getenv("REQUEST_TIMEOUT_SECS", "15"))

# Optional: gzip the whole JSON request body (receiver must support it)
USE_GZIP = os.getenv("USE_GZIP", "1") not in ("0", "false", "False")

_SENDER_ID_CACHE = None

# -----------------------------------------------------------------------
# Nginx access log lines always begin with an IPv4 or IPv6 address.
# Any physical line that does NOT match this pattern is a continuation
# fragment produced by an embedded \n inside a JSON field.
# -----------------------------------------------------------------------
import re as _re
_NGINX_LINE_START = _re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})\s"
)

# SETUP LOGGING
logging.basicConfig(
    filename=LOGGING_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ========== UTILITIES ==========

def get_file_id(path):
    try:
        st = os.stat(path)
        return (st.st_dev, st.st_ino)
    except FileNotFoundError:
        logging.error(f"File not found: {path}")
        return None

def get_last_offset():
    if os.path.exists(OFFSET_FILE):
        try:
            with open(OFFSET_FILE, "r") as f:
                raw = f.read().strip()
            if not raw:
                logging.warning("Offset file is empty. Starting from offset 0.")
                return 0
            offset = int(raw)
            if offset < 0:
                logging.warning(f"Offset file has negative value ({offset}). Starting from 0.")
                return 0
            logging.info(f"Loaded last offset: {offset}")
            return offset
        except (OSError, ValueError) as e:
            logging.warning(f"Failed to parse offset file. Starting from 0. Error: {e}")
            return 0
    logging.info("Offset file not found. Starting from offset 0.")
    return 0

def save_offset(offset):
    os.makedirs(os.path.dirname(OFFSET_FILE), exist_ok=True)
    tmp_path = OFFSET_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(str(int(offset)))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, OFFSET_FILE)
    logging.info(f"Saved new offset: {offset}")


# ── Fragment persistence ──────────────────────────────────────────────────────
# The pending fragment (a partial multi-line nginx log entry carried across
# batch boundaries) must survive crashes.  We store it alongside the offset
# file so restart can resume mid-entry without losing data.
FRAGMENT_FILE = OFFSET_FILE + ".fragment"


def save_fragment(fragment):
    """Atomically persist the pending continuation fragment to disk."""
    if not fragment:
        # No fragment — remove stale file if it exists
        try:
            if os.path.exists(FRAGMENT_FILE):
                os.remove(FRAGMENT_FILE)
        except OSError:
            pass
        return
    tmp = FRAGMENT_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(fragment)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, FRAGMENT_FILE)


def load_fragment():
    """Load a previously persisted fragment, or return empty string."""
    if not os.path.exists(FRAGMENT_FILE):
        return ""
    try:
        with open(FRAGMENT_FILE, "r", encoding="utf-8") as f:
            frag = f.read()
        if frag:
            logging.info(f"Loaded persisted fragment ({len(frag)} bytes) from {FRAGMENT_FILE}")
        return frag
    except Exception as e:
        logging.warning(f"Failed to load fragment file: {e}")
        return ""

def should_skip_line(line):
    return (
        "/health.php" in line and
        "nginx/" in line and
        "health check" in line
    )


def _get_sender_identity():
    """Best-effort stable identity for directory naming on the receiver."""
    global _SENDER_ID_CACHE
    if _SENDER_ID_CACHE:
        return _SENDER_ID_CACHE

    env_host = os.getenv("SENDER_ID")
    if env_host:
        _SENDER_ID_CACHE = env_host.strip()
        return _SENDER_ID_CACHE

    try:
        parsed = urlparse(SEND_URL)
        receiver_host = parsed.hostname
        receiver_port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if receiver_host:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((receiver_host, int(receiver_port)))
                _SENDER_ID_CACHE = s.getsockname()[0]
                return _SENDER_ID_CACHE
            finally:
                try:
                    s.close()
                except Exception:
                    pass
    except Exception:
        pass

    try:
        _SENDER_ID_CACHE = socket.gethostbyname(socket.gethostname())
        return _SENDER_ID_CACHE
    except Exception:
        _SENDER_ID_CACHE = socket.gethostname()
        return _SENDER_ID_CACHE


def _encode_payload(payload):
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if USE_GZIP:
        body = gzip.compress(body)
        headers["Content-Encoding"] = "gzip"
    return body, headers

@retry(stop=stop_after_attempt(600), wait=wait_fixed(6))
def send_chunk(lines, start_offset, end_offset, file_id):
    if not lines:
        return

    data = "\n".join(lines)
    sender_id = _get_sender_identity()
    batch_fingerprint = hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()

    payload = {
        "log": data,
        "host": sender_id,
        "meta": {
            "start_offset": start_offset,
            "end_offset": end_offset,
            "file_id": list(file_id) if file_id else None,
            "lines": len(lines),
            "sha256": batch_fingerprint,
        },
    }
    body, headers = _encode_payload(payload)

    try:
        logging.info(f"Sending {len(lines)} lines (offset {start_offset}-{end_offset}) to {SEND_URL}.")
        response = requests.post(
            SEND_URL,
            data=body,
            headers=headers,
            timeout=(REQUEST_TIMEOUT_SECS, REQUEST_TIMEOUT_SECS),
        )
        response.raise_for_status()
        logging.info(f"Successfully sent {len(lines)} lines (offset {start_offset}-{end_offset}).")
    except Exception as e:
        logging.error(f"Failed to send lines (offset {start_offset}-{end_offset}): {e}")
        logging.error(f"Last line (offset {end_offset}): {lines[-1]}")
        raise


# ========== HANDLER ==========

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.offset = get_last_offset()
        self.last_file_id = get_file_id(LOG_FILE)

        self._lock = threading.Lock()
        self._dirty = threading.Event()
        self._stop = threading.Event()

        # ---------------------------------------------------------------
        # Carry-over buffer for continuation-line reassembly.
        #
        # Because nginx log entries can contain embedded \n characters
        # (inside JSON fields), a single logical log line may be split
        # across multiple readline() calls — and even across batch
        # boundaries.  We hold the last physical line in _pending_fragment
        # until we can confirm the next physical line either starts a new
        # entry (IP at column 0) or is another continuation of the same
        # entry.
        #
        # The fragment is persisted to disk alongside the offset file so
        # it survives crashes without data loss.
        # ---------------------------------------------------------------
        self._pending_fragment: str = load_fragment()

        # Keep a file handle open to safely drain the "old" file on rename-rotation.
        self._fh = None
        self._open_log_file(seek_to_offset=True)

        self._worker = threading.Thread(target=self._run_tailer, name="log-shipper-tailer", daemon=True)
        self._worker.start()

    def on_modified(self, event):
        if os.path.realpath(event.src_path) != os.path.realpath(LOG_FILE):
            return
        self._dirty.set()

    def stop(self):
        self._stop.set()
        self._dirty.set()
        if self._worker.is_alive():
            self._worker.join(timeout=5)
        with self._lock:
            if self._fh:
                try:
                    self._fh.close()
                except Exception:
                    pass
                self._fh = None

    def _open_log_file(self, seek_to_offset: bool):
        fh = open(LOG_FILE, "rb")
        if seek_to_offset:
            try:
                fh.seek(self.offset)
            except Exception:
                self.offset = 0
                fh.seek(0)
        self._fh = fh
        self.last_file_id = get_file_id(LOG_FILE)

    def _detect_rotation_or_truncate(self):
        """Handle both rename-rotation (inode change) and copytruncate (size shrink)."""
        try:
            st = os.stat(LOG_FILE)
        except FileNotFoundError:
            return

        current_file_id = (st.st_dev, st.st_ino)

        if self.last_file_id == current_file_id and st.st_size < self.offset:
            logging.info(
                f"Detected truncation (size {st.st_size} < offset {self.offset}). Resetting offset to 0."
            )
            self.offset = 0
            save_offset(self.offset)
            self._pending_fragment = ""  # discard stale fragment on truncation
            save_fragment("")
            try:
                if self._fh:
                    self._fh.seek(0)
            except Exception:
                self._open_log_file(seek_to_offset=True)
            return

        if self.last_file_id and current_file_id != self.last_file_id:
            logging.info("Detected inode change (rotation). Will drain old file then switch.")
            return

    def _switch_to_new_file_if_rotated(self):
        try:
            current_file_id = get_file_id(LOG_FILE)
        except Exception:
            current_file_id = None

        if current_file_id and self.last_file_id and current_file_id != self.last_file_id:
            try:
                if self._fh:
                    self._fh.close()
            except Exception:
                pass
            self.offset = 0
            self._pending_fragment = ""  # new file; discard stale fragment
            save_offset(self.offset)
            save_fragment("")
            self._open_log_file(seek_to_offset=True)
            logging.info(f"Switched to new rotated file. New file_id={self.last_file_id}")

    def _read_next_batch(self):
        """Read up to CHUNK_SIZE *logical* lines (with continuation merging) and
        up to MAX_BATCH_BYTES from the current file handle.

        The key invariant: every entry in the returned ``lines`` list starts
        with an IPv4/IPv6 address (a real nginx log entry).  Physical lines
        that don't match that pattern are embedded-newline fragments and are
        rejoined onto the preceding logical line.

        A fragment that arrives at the very end of the batch (i.e. we hit the
        chunk / byte cap and haven't seen the next real line yet) is held in
        ``self._pending_fragment`` and prepended to the first line of the
        next call.  This is the cross-batch-boundary fix.
        """
        if not self._fh:
            self._open_log_file(seek_to_offset=True)

        start_offset = self.offset
        lines: List[str] = []
        total_bytes = 0
        fragments_merged = 0

        while len(lines) < CHUNK_SIZE and total_bytes < MAX_BATCH_BYTES:
            pos_before = self._fh.tell()
            raw = self._fh.readline()
            if not raw:
                # EOF — nothing more to read right now.
                break
            pos_after = self._fh.tell()
            total_bytes += (pos_after - pos_before)

            try:
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
            except Exception:
                line = raw.decode(errors="replace").rstrip("\n")

            if should_skip_line(line):
                # If we were accumulating a fragment, keep it; the skipped
                # health-check line is unrelated.
                continue

            if _NGINX_LINE_START.match(line):
                # This is the start of a new logical log entry.
                if self._pending_fragment:
                    # The previous batch ended mid-entry; flush the completed
                    # logical line (pending + any further continuation already
                    # appended there) now that we know the entry has ended.
                    lines.append(self._pending_fragment)
                    self._pending_fragment = ""
                # Start accumulating the new entry.
                self._pending_fragment = line
            else:
                # Continuation fragment — append to whatever is being built.
                if self._pending_fragment:
                    self._pending_fragment += line
                    fragments_merged += 1
                else:
                    # Fragment at the very start (e.g. first read after
                    # restart with a corrupted offset).  Keep it so we
                    # don't silently drop data.
                    logging.warning(
                        f"Continuation fragment with no preceding line "
                        f"(offset ~{pos_before}): {line[:120]!r}"
                    )
                    self._pending_fragment = line
                    fragments_merged += 1

        # After draining up to the chunk cap:
        # - If we hit EOF and still have a pending fragment, it *might* be a
        #   complete line whose terminating \n hasn't been flushed yet by nginx
        #   (partial write).  Leave it in _pending_fragment so the next wakeup
        #   can continue appending to it.  Only flush it once a subsequent
        #   readline() returns a new real line (handled at the top of the loop
        #   above) or once we detect rotation/truncation.
        # - If we hit the chunk cap mid-stream, _pending_fragment already
        #   holds the incomplete logical line and will be prepended next call.

        if fragments_merged:
            logging.info(f"Merged {fragments_merged} continuation fragment(s) in this batch.")

        end_offset = self._fh.tell()
        return lines, start_offset, end_offset

    def _drain_old_file_to_eof_if_rotated(self):
        """If inode changed, read until EOF from the currently-open (old) handle."""
        current_file_id = get_file_id(LOG_FILE)
        if not (current_file_id and self.last_file_id and current_file_id != self.last_file_id):
            return

        while True:
            lines, start_offset, end_offset = self._read_next_batch()
            if not lines:
                break
            send_chunk(lines, start_offset, end_offset, file_id=self.last_file_id)
            self.offset = end_offset
            save_offset(self.offset)
            save_fragment(self._pending_fragment)

        # Flush any pending fragment before switching files.
        if self._pending_fragment:
            logging.info("Flushing pending fragment before file rotation switch.")
            send_chunk(
                [self._pending_fragment],
                self.offset,
                self.offset,
                file_id=self.last_file_id,
            )
            self._pending_fragment = ""
            save_fragment("")

        self._switch_to_new_file_if_rotated()

    def _process_available(self):
        with self._lock:
            self._detect_rotation_or_truncate()
            self._drain_old_file_to_eof_if_rotated()

            lines, start_offset, end_offset = self._read_next_batch()
            if not lines:
                return 0

            send_chunk(lines, start_offset, end_offset, file_id=self.last_file_id)
            self.offset = end_offset
            save_offset(self.offset)
            save_fragment(self._pending_fragment)
            return len(lines)

    def _run_tailer(self):
        while not self._stop.is_set():
            self._dirty.wait(timeout=POLL_INTERVAL)
            self._dirty.clear()

            processed_any = False
            for _ in range(100):
                if self._stop.is_set():
                    break
                try:
                    n = self._process_available()
                except Exception:
                    logging.exception("Error during processing; will retry.")
                    break
                if n == 0:
                    break
                processed_any = True

            if processed_any:
                time.sleep(0.01)


# ========== MAIN ==========

def drain_backlog(handler: LogHandler):
    logging.info("Draining backlog from log file...")
    total = 0
    for _ in range(100000):
        try:
            n = handler._process_available()
        except Exception:
            logging.exception("Error while draining backlog.")
            break
        if n == 0:
            break
        total += n
    logging.info(f"Finished draining backlog. Lines shipped: {total}")


def main():
    logging.info("Starting log shipper...")
    handler = LogHandler()
    drain_backlog(handler)

    observer = Observer()
    observer.schedule(handler, path=os.path.dirname(LOG_FILE), recursive=False)
    observer.start()

    logging.info(f"Watching {LOG_FILE} for changes.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        handler.stop()
        logging.info("Log shipper interrupted by user.")
    observer.join()
    logging.info("Shutting down log shipper.")


if __name__ == "__main__":
    main()
