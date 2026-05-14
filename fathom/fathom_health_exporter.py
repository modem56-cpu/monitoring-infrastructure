#!/usr/bin/env python3
"""
Fathom Vault Sync — Prometheus textfile collector exporter.

Runs on fathom-server (192.168.10.24) as fathom-admin.
Writes to /var/lib/node_exporter/textfile_collector/fathom_health.prom
using atomic replace so Prometheus never sees a partial write.

Safety rules:
  - Read-only SQLite connection (uri=True, ?mode=ro)
  - Never writes to the DB, never calls INSERT/UPDATE/DELETE
  - Always exits 0 — errors go into metric values, not exit codes
  - Closes DB connection before writing the .prom file
"""

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
from shutil import disk_usage

# ---------------------------------------------------------------------------
# Paths — must match fathom-server layout
# ---------------------------------------------------------------------------
NAS_MOUNT     = "/opt/fathom-vault-sync/nas"
DB_PATH       = "/opt/fathom-vault-sync/nas/fathom.db"
STALE_DB_PATH = "/opt/fathom-vault-sync/meeting_transcript_repository-master/fathom.db"
PROM_PATH     = "/var/lib/prometheus/node-exporter/fathom_health.prom"
PROM_DIR      = os.path.dirname(PROM_PATH)

STATE_DIR       = "/var/lib/fathom-monitoring"
STATE_PATH      = os.path.join(STATE_DIR, "fathom_db_state.json")
WAZUH_EVENT_LOG = os.path.join(STATE_DIR, "fathom_db_events.log")

FLASK_HOST    = "127.0.0.1"
FLASK_PORT    = 5000

SYSTEMD_UNITS = [
    "fathom-sync.timer",
    "fathom-video.timer",
    "fathom-nas-mount.service",
    "fathom-sync-ui.service",
    "fathom-db-integrity-audit.timer",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def metric(name, value, labels=None):
    """Return a single metric line. value may be int, float, or str."""
    if labels:
        label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
        return f"{name}{{{label_str}}} {value}"
    return f"{name} {value}"


def header(name, help_text, mtype="gauge"):
    return [f"# HELP {name} {help_text}", f"# TYPE {name} {mtype}"]


def systemctl_is_active(unit, timeout=5):
    """Return 1 if unit is active, 0 if inactive, -1 on error."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", unit],
            capture_output=True, text=True, timeout=timeout
        )
        return 1 if r.stdout.strip() == "active" else 0
    except Exception:
        return -1


def port_listening(host, port, timeout=3):
    """Return 1 if port accepts a connection, 0 otherwise."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 1
    except Exception:
        return 0


def count_processes(pattern, timeout=5):
    """Return count of processes matching pattern via pgrep -f."""
    try:
        r = subprocess.run(
            ["pgrep", "-f", pattern],
            capture_output=True, text=True, timeout=timeout
        )
        lines = [l for l in r.stdout.strip().splitlines() if l]
        return len(lines)
    except Exception:
        return -1


def disk_used_percent(path, timeout=10):
    """Return used% for the filesystem at path, or -1 on error."""
    try:
        usage = disk_usage(path)
        return round(usage.used / usage.total * 100, 1)
    except Exception:
        return -1


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def load_state():
    """Load previous DB state from STATE_PATH. Returns {} on any error."""
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    """Atomically write state dict to STATE_PATH."""
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", dir=STATE_DIR, suffix=".tmp",
            delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(state, tmp)
            tmp_path = tmp.name
        os.replace(tmp_path, STATE_PATH)
    except Exception:
        pass  # state loss is non-fatal


# ---------------------------------------------------------------------------
# DB fingerprinting
# ---------------------------------------------------------------------------

CHUNK_SIZE = 64 * 1024  # 64 KB


def fingerprint_db(path):
    """
    Return a partial SHA-256 hex digest of the DB file (first + last 64 KB).
    Fast enough to run every 5 minutes on a multi-GB file.
    Returns None on error.
    """
    try:
        h = hashlib.sha256()
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            # First 64 KB
            h.update(f.read(CHUNK_SIZE))
            # Last 64 KB (if file is large enough to have a distinct tail)
            if size > CHUNK_SIZE:
                f.seek(max(0, size - CHUNK_SIZE))
                h.update(f.read(CHUNK_SIZE))
        return h.hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# SQLite integrity check (with timeout)
# ---------------------------------------------------------------------------

def check_integrity(db_path, timeout=50):
    """
    Run PRAGMA integrity_check on db_path in a thread with a timeout.
    Returns 1 if 'ok', 0 on failure or timeout, -1 on connection error.
    """
    result = [-1]  # mutable container for thread result

    def _run():
        conn = None
        try:
            # immutable=1 bypasses POSIX file locking — required for SSHFS
            # mounts where SQLite locking is unreliable under concurrent writes.
            # Safe here because we only read and do not need transactional
            # consistency from the integrity check.
            conn = sqlite3.connect(
                f"file:{db_path}?mode=ro&immutable=1", uri=True, timeout=5.0
            )
            conn.execute("PRAGMA query_only = ON")
            row = conn.execute("PRAGMA integrity_check").fetchone()
            result[0] = 1 if (row and row[0] == "ok") else 0
        except Exception:
            result[0] = 0
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        # Thread still blocked — integrity check timed out
        return 0
    return result[0]


# ---------------------------------------------------------------------------
# Wazuh event emission
# ---------------------------------------------------------------------------

def emit_wazuh_event(event_type, details):
    """
    Append a JSON event line to WAZUH_EVENT_LOG (NDJSON).
    Wazuh reads this file as a syslog localfile and forwards the JSON.
    """
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        event = {
            "timestamp": int(time.time()),
            "source": "fathom_health_exporter",
            "event_type": event_type,
        }
        event.update(details)
        with open(WAZUH_EVENT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass  # event loss is non-fatal


# ---------------------------------------------------------------------------
# Main collector
# ---------------------------------------------------------------------------

def collect():
    lines = []
    success = 1  # will be set to 0 on any unrecoverable error

    # ------------------------------------------------------------------ NAS
    nas_mounted = 1 if os.path.ismount(NAS_MOUNT) else 0
    lines += header("fathom_nas_mounted",
                    "1 if NAS SSHFS mount is accessible, 0 otherwise")
    lines.append(metric("fathom_nas_mounted", nas_mounted))

    # ------------------------------------------------------------------ Stale local DB
    stale_exists = 1 if os.path.isfile(STALE_DB_PATH) else 0
    lines += header("fathom_stale_local_db_exists",
                    "1 if project-root fathom.db exists (should not)")
    lines.append(metric("fathom_stale_local_db_exists", stale_exists))

    # ------------------------------------------------------------------ Load previous state
    prev = load_state()
    new_state = {}

    # ------------------------------------------------------------------ DB metrics
    # Sentinel values written if DB is unavailable
    db_guard       = 0
    db_size_bytes  = -1
    total          = -1
    has_video      = -1
    has_transcript = -1
    has_summary    = -1
    video_pct      = -1.0
    transcript_pct = -1.0
    summary_pct    = -1.0
    sync_age       = -1
    sync_success   = 0

    # Delta / integrity sentinels (-1 = unknown/unavailable)
    db_prev_size_bytes     = int(prev.get("db_size_bytes", -1))
    db_size_delta          = -1
    db_mtime               = -1
    db_inode_changed       = -1
    db_checksum_changed    = -1
    total_delta            = -1
    has_video_delta        = -1
    has_transcript_delta   = -1
    has_summary_delta      = -1
    sqlite_integrity_ok    = -1
    regression_detected    = 0

    if nas_mounted:
        # Verify DB path points to NAS (live guard)
        try:
            real_db = os.path.realpath(DB_PATH)
            real_nas = os.path.realpath(NAS_MOUNT)
            if real_db.startswith(real_nas) and os.path.isfile(DB_PATH):
                db_size_bytes = os.path.getsize(DB_PATH)
                if db_size_bytes >= 500 * 1024 * 1024:  # 500 MB minimum
                    db_guard = 1
                # else guard fails — too small, likely wrong file
            # stale local DB check for path guard
            if os.path.isfile(STALE_DB_PATH) and \
               os.path.realpath(STALE_DB_PATH) == real_db:
                db_guard = 0  # would be using stale DB
        except Exception:
            db_guard = 0
            success = 1  # path check error isn't fatal for other metrics

        # ---- File-level fingerprinting (runs regardless of db_guard) --------
        if os.path.isfile(DB_PATH):
            try:
                stat = os.stat(DB_PATH)
                db_mtime       = int(stat.st_mtime)
                current_inode  = stat.st_ino
                prev_inode     = prev.get("db_inode")
                db_inode_changed = 0 if (prev_inode is None or prev_inode == current_inode) else 1

                current_checksum = fingerprint_db(DB_PATH)
                prev_checksum    = prev.get("db_checksum")
                if current_checksum is None:
                    db_checksum_changed = -1
                elif prev_checksum is None:
                    db_checksum_changed = 0  # no baseline yet
                else:
                    db_checksum_changed = 0 if prev_checksum == current_checksum else 1

                # Size delta
                if db_prev_size_bytes >= 0 and db_size_bytes >= 0:
                    db_size_delta = db_size_bytes - db_prev_size_bytes

                # Persist fingerprint state
                new_state["db_size_bytes"]  = db_size_bytes
                new_state["db_mtime"]       = db_mtime
                new_state["db_inode"]       = current_inode
                new_state["db_checksum"]    = current_checksum

                # Emit Wazuh events on fingerprint regressions
                if db_inode_changed == 1:
                    regression_detected = 1
                    emit_wazuh_event("db_inode_changed", {
                        "prev_inode": prev_inode,
                        "current_inode": current_inode,
                        "db_path": DB_PATH,
                    })
                if db_checksum_changed == 1:
                    regression_detected = 1
                    emit_wazuh_event("db_checksum_changed", {
                        "prev_checksum": prev_checksum,
                        "current_checksum": current_checksum,
                        "db_path": DB_PATH,
                    })
                if db_size_delta != -1 and db_size_delta < 0:
                    regression_detected = 1
                    emit_wazuh_event("db_size_decreased", {
                        "prev_size_bytes": db_prev_size_bytes,
                        "current_size_bytes": db_size_bytes,
                        "delta_bytes": db_size_delta,
                        "db_path": DB_PATH,
                    })
            except Exception:
                pass  # fingerprint failure is non-fatal

        # ---- SQLite integrity check ------------------------------------------
        if db_guard == 1:
            sqlite_integrity_ok = check_integrity(DB_PATH, timeout=20)
            if sqlite_integrity_ok == 0:
                regression_detected = 1
                emit_wazuh_event("db_integrity_check_failed", {
                    "db_path": DB_PATH,
                })

        # ---- Query DB (read-only) --------------------------------------------
        if db_guard == 1:
            conn = None
            try:
                conn = sqlite3.connect(
                    f"file:{DB_PATH}?mode=ro", uri=True, timeout=5.0
                )
                conn.execute("PRAGMA query_only = ON")

                row = conn.execute(
                    "SELECT COUNT(*), SUM(has_video), SUM(has_transcript), "
                    "SUM(has_summary) FROM meetings"
                ).fetchone()
                if row and row[0]:
                    total, has_video, has_transcript, has_summary = (
                        int(row[0]), int(row[1] or 0),
                        int(row[2] or 0), int(row[3] or 0)
                    )
                    video_pct      = round(has_video      / total * 100, 1)
                    transcript_pct = round(has_transcript / total * 100, 1)
                    summary_pct    = round(has_summary    / total * 100, 1)

                    # Compute deltas against previous state
                    prev_total         = prev.get("db_total_meetings")
                    prev_has_video     = prev.get("db_has_video")
                    prev_has_transcript = prev.get("db_has_transcript")
                    prev_has_summary   = prev.get("db_has_summary")

                    if prev_total is not None:
                        total_delta        = total          - int(prev_total)
                        has_video_delta    = has_video      - int(prev_has_video or 0)
                        has_transcript_delta = has_transcript - int(prev_has_transcript or 0)
                        has_summary_delta  = has_summary    - int(prev_has_summary or 0)

                        # Emit Wazuh events on count regressions
                        if total_delta < 0:
                            regression_detected = 1
                            emit_wazuh_event("db_meeting_count_decreased", {
                                "prev_total": int(prev_total),
                                "current_total": total,
                                "delta": total_delta,
                            })
                        if has_video_delta < 0:
                            regression_detected = 1
                            emit_wazuh_event("db_video_count_decreased", {
                                "prev_has_video": int(prev_has_video or 0),
                                "current_has_video": has_video,
                                "delta": has_video_delta,
                            })
                        if has_transcript_delta < 0:
                            regression_detected = 1
                            emit_wazuh_event("db_transcript_count_decreased", {
                                "prev_has_transcript": int(prev_has_transcript or 0),
                                "current_has_transcript": has_transcript,
                                "delta": has_transcript_delta,
                            })
                        if has_summary_delta < 0:
                            regression_detected = 1
                            emit_wazuh_event("db_summary_count_decreased", {
                                "prev_has_summary": int(prev_has_summary or 0),
                                "current_has_summary": has_summary,
                                "delta": has_summary_delta,
                            })

                    # Persist meeting counts for next run
                    new_state["db_total_meetings"]  = total
                    new_state["db_has_video"]        = has_video
                    new_state["db_has_transcript"]   = has_transcript
                    new_state["db_has_summary"]      = has_summary

                # Latest sync age
                sync_row = conn.execute(
                    "SELECT completed_at FROM sync_runs "
                    "WHERE status='success' ORDER BY completed_at DESC LIMIT 1"
                ).fetchone()
                if sync_row and sync_row[0]:
                    from datetime import datetime, timezone
                    ts_str = sync_row[0].replace("Z", "+00:00")
                    try:
                        ts = datetime.fromisoformat(ts_str)
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=timezone.utc)
                        sync_age = int(
                            (datetime.now(timezone.utc) - ts).total_seconds()
                        )
                        sync_success = 1
                    except Exception:
                        sync_age = -1
                        sync_success = 0
            except sqlite3.OperationalError:
                # DB locked or missing — keep sentinel values
                db_guard = 0
                success = 0
            except Exception:
                success = 0
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
    else:
        # NAS not mounted — no DB available
        success = 0

    # Persist state for next run
    if new_state:
        save_state(new_state)

    # ------------------------------------------------------------------ Emit metrics
    lines += header("fathom_db_live_guard_pass",
                    "1 if live DB guard confirms correct production DB")
    lines.append(metric("fathom_db_live_guard_pass", db_guard))

    lines += header("fathom_db_size_bytes",
                    "Size of the live production DB file in bytes")
    lines.append(metric("fathom_db_size_bytes", db_size_bytes))

    lines += header("fathom_db_previous_size_bytes",
                    "DB size from previous exporter run (-1 if no baseline)")
    lines.append(metric("fathom_db_previous_size_bytes", db_prev_size_bytes))

    lines += header("fathom_db_size_delta_bytes",
                    "DB size change since last run in bytes (-1 if unknown)")
    lines.append(metric("fathom_db_size_delta_bytes", db_size_delta))

    lines += header("fathom_db_mtime_unixtime",
                    "DB file modification time as Unix timestamp (-1 if unavailable)")
    lines.append(metric("fathom_db_mtime_unixtime", db_mtime))

    lines += header("fathom_db_inode_changed",
                    "1 if DB inode changed since last run (possible file swap), -1 if unknown")
    lines.append(metric("fathom_db_inode_changed", db_inode_changed))

    lines += header("fathom_db_checksum_changed",
                    "1 if DB partial checksum changed since last run, -1 if unknown")
    lines.append(metric("fathom_db_checksum_changed", db_checksum_changed))

    lines += header("fathom_db_sqlite_integrity_ok",
                    "1 if PRAGMA integrity_check returned ok, 0 on failure, -1 if not run")
    lines.append(metric("fathom_db_sqlite_integrity_ok", sqlite_integrity_ok))

    lines += header("fathom_db_regression_detected",
                    "1 if any DB regression event was detected this run")
    lines.append(metric("fathom_db_regression_detected", regression_detected))

    lines += header("fathom_db_total_meetings",
                    "Total rows in the meetings table")
    lines.append(metric("fathom_db_total_meetings", total))

    lines += header("fathom_db_total_meetings_delta",
                    "Change in total_meetings since last run (-1 if no baseline)")
    lines.append(metric("fathom_db_total_meetings_delta", total_delta))

    lines += header("fathom_db_has_video", "Meetings with has_video=1")
    lines.append(metric("fathom_db_has_video", has_video))

    lines += header("fathom_db_has_video_delta",
                    "Change in has_video count since last run (-1 if no baseline)")
    lines.append(metric("fathom_db_has_video_delta", has_video_delta))

    lines += header("fathom_db_has_transcript",
                    "Meetings with has_transcript=1")
    lines.append(metric("fathom_db_has_transcript", has_transcript))

    lines += header("fathom_db_has_transcript_delta",
                    "Change in has_transcript count since last run (-1 if no baseline)")
    lines.append(metric("fathom_db_has_transcript_delta", has_transcript_delta))

    lines += header("fathom_db_has_summary", "Meetings with has_summary=1")
    lines.append(metric("fathom_db_has_summary", has_summary))

    lines += header("fathom_db_has_summary_delta",
                    "Change in has_summary count since last run (-1 if no baseline)")
    lines.append(metric("fathom_db_has_summary_delta", has_summary_delta))

    lines += header("fathom_video_coverage_percent",
                    "Video coverage as a percentage of total meetings")
    lines.append(metric("fathom_video_coverage_percent", video_pct))

    lines += header("fathom_transcript_coverage_percent",
                    "Transcript coverage as a percentage")
    lines.append(metric("fathom_transcript_coverage_percent", transcript_pct))

    lines += header("fathom_summary_coverage_percent",
                    "Summary coverage as a percentage")
    lines.append(metric("fathom_summary_coverage_percent", summary_pct))

    lines += header("fathom_latest_sync_age_seconds",
                    "Seconds since the last successful sync_run entry")
    lines.append(metric("fathom_latest_sync_age_seconds", sync_age))

    lines += header("fathom_latest_sync_success",
                    "1 if last sync_run status was success")
    lines.append(metric("fathom_latest_sync_success", sync_success))

    # ------------------------------------------------------------------ Systemd timers / services
    lines += header("fathom_sync_timer_active",
                    "1 if fathom-sync.timer is active")
    lines.append(metric("fathom_sync_timer_active",
                        systemctl_is_active("fathom-sync.timer")))

    lines += header("fathom_video_timer_active",
                    "1 if fathom-video.timer is active")
    lines.append(metric("fathom_video_timer_active",
                        systemctl_is_active("fathom-video.timer")))

    lines += header("fathom_audit_timer_active",
                    "1 if fathom-db-integrity-audit.timer is active")
    lines.append(metric("fathom_audit_timer_active",
                        systemctl_is_active("fathom-db-integrity-audit.timer")))

    lines += header("fathom_flask_port_listening",
                    "1 if port 5000 accepts connections")
    lines.append(metric("fathom_flask_port_listening",
                        port_listening(FLASK_HOST, FLASK_PORT)))

    lines += header("fathom_overlapping_sync_processes",
                    "Number of run.py processes currently running")
    lines.append(metric("fathom_overlapping_sync_processes",
                        count_processes(r"python.*run\.py")))

    # ------------------------------------------------------------------ Disk
    root_pct = disk_used_percent("/")
    nas_pct  = disk_used_percent(NAS_MOUNT) if nas_mounted else -1

    lines += header("fathom_root_disk_used_percent",
                    "Root filesystem usage percentage")
    lines.append(metric("fathom_root_disk_used_percent", root_pct))

    lines += header("fathom_nas_disk_used_percent",
                    "NAS filesystem usage percentage (via df on mount)")
    lines.append(metric("fathom_nas_disk_used_percent", nas_pct))

    # ------------------------------------------------------------------ Per-unit labeled metrics
    lines += header("fathom_systemd_unit_active",
                    "1 if the given systemd unit is active")
    for unit in SYSTEMD_UNITS:
        lines.append(metric("fathom_systemd_unit_active",
                            systemctl_is_active(unit),
                            labels={"unit": unit}))

    # ------------------------------------------------------------------ Exporter metadata
    lines += header("fathom_exporter_last_run_timestamp",
                    "Unix timestamp of last exporter run")
    lines.append(metric("fathom_exporter_last_run_timestamp",
                        int(time.time())))

    lines += header("fathom_exporter_success",
                    "1 if the exporter completed without errors")
    lines.append(metric("fathom_exporter_success", success))

    return lines


def write_prom(lines):
    """Atomically write lines to PROM_PATH."""
    os.makedirs(PROM_DIR, exist_ok=True)
    content = "\n".join(lines) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w", dir=PROM_DIR, suffix=".tmp",
        delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    # NamedTemporaryFile creates 0o600; chmod to 0o644 so node_exporter
    # (running as a different user) can read the textfile.
    os.chmod(tmp_path, 0o644)
    os.replace(tmp_path, PROM_PATH)


def main():
    try:
        lines = collect()
    except Exception as e:
        # Top-level safety net — always write something
        now = int(time.time())
        lines = [
            "# HELP fathom_exporter_success 1 if the exporter completed without errors",
            "# TYPE fathom_exporter_success gauge",
            f"fathom_exporter_success 0",
            "# HELP fathom_exporter_last_run_timestamp Unix timestamp of last exporter run",
            "# TYPE fathom_exporter_last_run_timestamp gauge",
            f"fathom_exporter_last_run_timestamp {now}",
        ]
    write_prom(lines)
    # Always exit 0 — errors are in metric values
    raise SystemExit(0)


if __name__ == "__main__":
    main()
