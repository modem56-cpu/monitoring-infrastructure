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

import os
import socket
import sqlite3
import subprocess
import tempfile
import time
from shutil import disk_usage

# ---------------------------------------------------------------------------
# Paths — must match fathom-server layout
# ---------------------------------------------------------------------------
NAS_MOUNT     = "/opt/fathom-vault-sync/nas"
DB_PATH       = "/opt/fathom-vault-sync/nas/fathom.db"
STALE_DB_PATH = "/opt/fathom-vault-sync/meeting_transcript_repository-master/fathom.db"
PROM_PATH     = "/var/lib/node_exporter/textfile_collector/fathom_health.prom"
PROM_DIR      = os.path.dirname(PROM_PATH)

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
# Main
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

    # ------------------------------------------------------------------ DB metrics
    # Sentinel values written if DB is unavailable
    db_guard      = 0
    db_size_bytes = -1
    total         = -1
    has_video     = -1
    has_transcript = -1
    has_summary   = -1
    video_pct     = -1.0
    transcript_pct = -1.0
    summary_pct   = -1.0
    sync_age      = -1
    sync_success  = 0

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

        # Query DB (read-only)
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

    lines += header("fathom_db_live_guard_pass",
                    "1 if live DB guard confirms correct production DB")
    lines.append(metric("fathom_db_live_guard_pass", db_guard))

    lines += header("fathom_db_size_bytes",
                    "Size of the live production DB file in bytes")
    lines.append(metric("fathom_db_size_bytes", db_size_bytes))

    lines += header("fathom_db_total_meetings",
                    "Total rows in the meetings table")
    lines.append(metric("fathom_db_total_meetings", total))

    lines += header("fathom_db_has_video", "Meetings with has_video=1")
    lines.append(metric("fathom_db_has_video", has_video))

    lines += header("fathom_db_has_transcript",
                    "Meetings with has_transcript=1")
    lines.append(metric("fathom_db_has_transcript", has_transcript))

    lines += header("fathom_db_has_summary", "Meetings with has_summary=1")
    lines.append(metric("fathom_db_has_summary", has_summary))

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
