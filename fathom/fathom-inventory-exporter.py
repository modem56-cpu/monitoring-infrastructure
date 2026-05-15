#!/usr/bin/env python3
"""
fathom-inventory-exporter.py

Runs on fathom-server (192.168.10.24) as fathom-admin.
Queries the Fathom Vault SQLite DB (read-only) and produces:

  1. /var/lib/fathom-monitoring/fathom_inventory_state.json
     Aggregate counts read by fathom_health_exporter.py → Prometheus metrics.

  2. /var/lib/fathom-monitoring/inventory/fathom_recording_inventory.json
     Full per-meeting recording status (all meetings).

  3. /var/lib/fathom-monitoring/inventory/fathom_recording_inventory.csv
     CSV version of the full inventory.

  4. /var/lib/fathom-monitoring/inventory/fathom_recording_issues.json
     Meetings with at least one missing artifact (video/transcript/summary).

  5. /var/lib/fathom-monitoring/inventory/fathom_recording_issues.csv
     CSV version of recording issues only.

These files are synced to the monitoring server report directory
(/opt/monitoring/reports/) by deploy-fathom-monitoring.sh so that
report-server.py can serve them on port 8088.

Usage (on fathom-server as fathom-admin, or via systemd timer):
    python3 /opt/fathom-vault-sync/monitoring/fathom-inventory-exporter.py

Idempotent — safe to run every hour. Always exits 0.
"""

import csv
import io
import json
import os
import sqlite3
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DB_PATH       = "/opt/fathom-vault-sync/nas/fathom.db"
STATE_DIR     = "/var/lib/fathom-monitoring"
INVENTORY_DIR = os.path.join(STATE_DIR, "inventory")

STATE_FILE     = os.path.join(STATE_DIR, "fathom_inventory_state.json")
INVENTORY_JSON = os.path.join(INVENTORY_DIR, "fathom_recording_inventory.json")
INVENTORY_CSV  = os.path.join(INVENTORY_DIR, "fathom_recording_inventory.csv")
ISSUES_JSON    = os.path.join(INVENTORY_DIR, "fathom_recording_issues.json")
ISSUES_CSV     = os.path.join(INVENTORY_DIR, "fathom_recording_issues.csv")

REPORT_SERVER_BASE = "http://192.168.10.20:8088"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def atomic_write_bytes(path, content_bytes):
    """Write bytes to path atomically using tmp file + os.replace."""
    dirpath = os.path.dirname(path)
    os.makedirs(dirpath, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dirpath, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content_bytes)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def atomic_write(path, content, encoding="utf-8"):
    """Write str to path atomically."""
    atomic_write_bytes(path, content.encode(encoding))


def classify_meeting(rec):
    """
    Return a list of issue strings for a meeting record dict.
    An empty list means the meeting is complete.
    """
    issues = []
    if not rec.get("has_video"):
        issues.append("missing_video")
    if not rec.get("has_transcript"):
        issues.append("missing_transcript")
    # Only flag missing summary when a transcript is present
    # (no transcript → summary generation not possible)
    if rec.get("has_transcript") and not rec.get("has_summary"):
        issues.append("missing_summary")
    return issues


def rows_to_csv(fieldnames, rows):
    """Convert list-of-dicts to a CSV string."""
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run():
    now_ts  = int(time.time())
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now_ts))

    # Sentinel state — always written so health exporter sees the run timestamp
    state = {
        "last_run_unixtime":     now_ts,
        "last_run_iso":          now_iso,
        "last_success_unixtime": -1,
        "inventory_total":       -1,
        "inventory_complete":    -1,
        "missing_video":         -1,
        "missing_transcript":    -1,
        "missing_summary":       -1,
        "has_issues":            -1,
        "error":                 None,
    }

    if not os.path.isfile(DB_PATH):
        state["error"] = f"DB not found: {DB_PATH}"
        try:
            atomic_write(STATE_FILE, json.dumps(state, indent=2))
        except Exception:
            pass
        print(f"[ERROR] {now_iso} — DB not found: {DB_PATH}", file=sys.stderr)
        return

    conn = None
    try:
        conn = sqlite3.connect(
            f"file:{DB_PATH}?mode=ro", uri=True, timeout=30.0
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")

        # ---- Discover available columns in meetings table -------------------
        col_info  = conn.execute("PRAGMA table_info(meetings)").fetchall()
        col_names = {row[1] for row in col_info}

        # Build SELECT dynamically based on available columns
        selects = ["m.id", "m.has_video", "m.has_transcript", "m.has_summary"]
        joins   = []

        # Account email (via FK to accounts)
        if "account_id" in col_names:
            acct_cols = {r[1] for r in conn.execute("PRAGMA table_info(accounts)").fetchall()}
            if "email" in acct_cols:
                selects.append("a.email AS account_email")
                joins.append("LEFT JOIN accounts a ON m.account_id = a.id")
            else:
                selects.append("'' AS account_email")
        else:
            selects.append("'' AS account_email")

        # Meeting title
        selects.append("m.title" if "title" in col_names else "'' AS title")

        # Started/date timestamp
        if "started_at" in col_names:
            selects.append("m.started_at")
        elif "date" in col_names:
            selects.append("m.date AS started_at")
        elif "created_at" in col_names:
            selects.append("m.created_at AS started_at")
        else:
            selects.append("NULL AS started_at")

        # Fathom-native meeting UUID / ID
        for id_col in ("fathom_id", "meeting_id", "external_id", "uuid"):
            if id_col in col_names:
                selects.append(f"m.{id_col} AS fathom_meeting_id")
                break
        else:
            selects.append("'' AS fathom_meeting_id")

        # Accessible flag (controls whether missing summary is actionable)
        selects.append("m.accessible" if "accessible" in col_names else "1 AS accessible")

        join_clause = " ".join(joins)
        sql = (
            f"SELECT {', '.join(selects)} "
            f"FROM meetings m {join_clause} "
            f"ORDER BY m.id DESC"
        )

        rows_raw = conn.execute(sql).fetchall()

        # ---- Classify meetings ---------------------------------------------
        inventory = []
        issues    = []

        for r in rows_raw:
            rec       = dict(r)
            row_issues = classify_meeting(rec)
            entry = {
                "meeting_db_id":     rec.get("id"),
                "fathom_meeting_id": str(rec.get("fathom_meeting_id") or ""),
                "account_email":     str(rec.get("account_email")     or ""),
                "title":             str(rec.get("title")             or ""),
                "started_at":        str(rec.get("started_at")        or ""),
                "has_video":         bool(rec.get("has_video")),
                "has_transcript":    bool(rec.get("has_transcript")),
                "has_summary":       bool(rec.get("has_summary")),
                "accessible":        bool(rec.get("accessible", True)),
                "status":            "complete" if not row_issues else "issues",
                "issues":            row_issues,
            }
            inventory.append(entry)
            if row_issues:
                issues.append(entry)

        # ---- Aggregate counts ----------------------------------------------
        total_m    = len(inventory)
        complete_m = sum(1 for e in inventory if e["status"] == "complete")
        miss_vid   = sum(1 for e in inventory if "missing_video"      in e["issues"])
        miss_tr    = sum(1 for e in inventory if "missing_transcript" in e["issues"])
        miss_sum   = sum(1 for e in inventory if "missing_summary"    in e["issues"])
        n_issues   = len(issues)

        # Issues broken out by type for Prometheus alert rules
        # missing_summary_actionable = transcript present but no summary (backfill targets)
        miss_sum_actionable = miss_sum  # already filtered by classify_meeting

        # ---- Write JSON files ----------------------------------------------
        summary_block = {
            "total_meetings":              total_m,
            "complete":                    complete_m,
            "with_issues":                 n_issues,
            "missing_video":               miss_vid,
            "missing_transcript":          miss_tr,
            "missing_summary_actionable":  miss_sum_actionable,
        }

        download_links = {
            "inventory_json": f"{REPORT_SERVER_BASE}/fathom_recording_inventory.json?download=1",
            "inventory_csv":  f"{REPORT_SERVER_BASE}/fathom_recording_inventory.csv?download=1",
            "issues_json":    f"{REPORT_SERVER_BASE}/fathom_recording_issues.json?download=1",
            "issues_csv":     f"{REPORT_SERVER_BASE}/fathom_recording_issues.csv?download=1",
        }

        inv_payload = {
            "generated_at":  now_iso,
            "source":        "fathom_inventory_exporter — fathom-server (192.168.10.24)",
            "db_path":       DB_PATH,
            "summary":       summary_block,
            "download_links": download_links,
            "meetings":      inventory,
        }

        issues_payload = {
            "generated_at":  now_iso,
            "source":        "fathom_inventory_exporter — fathom-server (192.168.10.24)",
            "db_path":       DB_PATH,
            "summary":       summary_block,
            "download_links": download_links,
            "issues":        issues,
        }

        atomic_write(INVENTORY_JSON, json.dumps(inv_payload,   indent=2, default=str))
        atomic_write(ISSUES_JSON,    json.dumps(issues_payload, indent=2, default=str))

        # ---- Write CSV files -----------------------------------------------
        csv_fields = [
            "meeting_db_id", "fathom_meeting_id", "account_email", "title",
            "started_at", "has_video", "has_transcript", "has_summary",
            "accessible", "status", "issues",
        ]

        def flatten(e):
            flat = dict(e)
            flat["issues"] = ";".join(e["issues"])
            return flat

        atomic_write(INVENTORY_CSV, rows_to_csv(csv_fields, [flatten(e) for e in inventory]))
        atomic_write(ISSUES_CSV,    rows_to_csv(csv_fields, [flatten(e) for e in issues]))

        # ---- Update aggregate state for health exporter --------------------
        state.update({
            "last_success_unixtime":      now_ts,
            "inventory_total":            total_m,
            "inventory_complete":         complete_m,
            "missing_video":              miss_vid,
            "missing_transcript":         miss_tr,
            "missing_summary":            miss_sum_actionable,
            "has_issues":                 n_issues,
            "error":                      None,
        })

        print(
            f"[OK] {now_iso} — {total_m} total, {complete_m} complete, "
            f"{n_issues} with issues "
            f"(video:{miss_vid} transcript:{miss_tr} summary:{miss_sum_actionable})"
        )

    except Exception as e:
        state["error"] = str(e)
        print(f"[ERROR] {now_iso} — {e}", file=sys.stderr)

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        try:
            atomic_write(STATE_FILE, json.dumps(state, indent=2))
        except Exception as e2:
            print(f"[ERROR] Could not write state file: {e2}", file=sys.stderr)


if __name__ == "__main__":
    run()
    sys.exit(0)
