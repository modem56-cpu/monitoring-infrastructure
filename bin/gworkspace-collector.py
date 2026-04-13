#!/usr/bin/env python3
"""
Google Workspace → Prometheus textfile + Wazuh JSON log
Collects: admin audit logs, login events, drive storage (50GB cap), security alerts
"""
import json, sys, datetime, os, time, random
from pathlib import Path
from datetime import date, timedelta

SA_KEY = os.environ.get("SA_KEY", "/opt/monitoring/gam-project-gf5mq-97886701cbdd.json")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "brian.monte@yokly.gives")
LOGFILE = Path(os.environ.get("LOGFILE", "/var/log/gworkspace-wazuh.log"))
PROMFILE = Path(os.environ.get("PROMFILE", "/opt/monitoring/textfile_collector/gworkspace.prom"))

QUOTA_BYTES = 50 * 1024 ** 3  # 50 GiB

EXEMPT = {
    "dan@agapay.gives",
    "calvin@yokly.gives",
    "it_dept@yokly.gives",
    "dm@yokly.gives",
    "tim@agapay.gives",
    "eddie@agapay.gives",
}

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("ERROR: google-api-python-client not installed", file=sys.stderr)
    sys.exit(1)

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/apps.alerts",
    "https://www.googleapis.com/auth/drive.readonly",
]

ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
prom_lines = []
wazuh_events = []

def emit_wazuh(alertname, severity, summary, **extra):
    event = {"timestamp": ts, "source": "google_workspace",
             "alertname": alertname, "severity": severity, "summary": summary}
    event.update(extra)
    wazuh_events.append(json.dumps(event))

def emit_prom(metric, value, labels=None):
    if labels:
        lbl = ",".join(f'{k}="{v}"' for k, v in labels.items())
        prom_lines.append(f'{metric}{{{lbl}}} {value}')
    else:
        prom_lines.append(f'{metric} {value}')

def fmt_gib(n):
    return f"{n / (1024 ** 3):.2f}"

def exec_with_retries(req, max_tries=4):
    for attempt in range(1, max_tries + 1):
        try:
            return req.execute(num_retries=2)
        except HttpError as e:
            status = getattr(e.resp, "status", None)
            if status in (429, 500, 502, 503, 504) and attempt < max_tries:
                time.sleep(min(2 ** attempt, 15) + random.random())
                continue
            raise

try:
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY, scopes=SCOPES, subject=ADMIN_EMAIL
    )
except Exception as e:
    print(f"ERROR: Auth failed: {e}", file=sys.stderr)
    prom_lines.append("# HELP gworkspace_collector_up Google Workspace collector status")
    prom_lines.append("# TYPE gworkspace_collector_up gauge")
    prom_lines.append("gworkspace_collector_up 0")
    PROMFILE.write_text("\n".join(prom_lines) + "\n")
    sys.exit(1)

errors = 0

# ============================================================
# 1. Admin Audit Logs (last 10 minutes)
# ============================================================
try:
    service = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
    start = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Login events
    results = service.activities().list(
        userKey="all", applicationName="login",
        startTime=start, maxResults=50
    ).execute()
    login_events = results.get("items", [])
    prom_lines.append("# HELP gworkspace_login_events_total Login events in last 10 min")
    prom_lines.append("# TYPE gworkspace_login_events_total gauge")
    emit_prom("gworkspace_login_events_total", len(login_events))

    for event in login_events:
        actor = event.get("actor", {}).get("email", "unknown")
        ip = event.get("ipAddress", "unknown")
        for e in event.get("events", []):
            ename = e.get("name", "")
            if ename in ("login_failure", "login_success", "suspicious_login", "account_disabled_password_leak"):
                severity = "warning" if "fail" in ename or "suspicious" in ename else "info"
                if "suspicious" in ename or "leak" in ename:
                    severity = "critical"
                emit_wazuh(f"GWorkspace_{ename}", severity,
                           f"Google Workspace {ename}: user={actor} ip={ip}",
                           user=actor, srcip=ip)

    # Admin events
    results = service.activities().list(
        userKey="all", applicationName="admin",
        startTime=start, maxResults=50
    ).execute()
    admin_events = results.get("items", [])
    prom_lines.append("# HELP gworkspace_admin_events_total Admin events in last 10 min")
    prom_lines.append("# TYPE gworkspace_admin_events_total gauge")
    emit_prom("gworkspace_admin_events_total", len(admin_events))

    for event in admin_events:
        actor = event.get("actor", {}).get("email", "unknown")
        for e in event.get("events", []):
            ename = e.get("name", "")
            params = {p["name"]: p.get("value", p.get("multiValue", "")) for p in e.get("parameters", [])}
            emit_wazuh("GWorkspace_admin_action", "info",
                       f"Admin action: {ename} by {actor}",
                       user=actor, admin_action=ename, details=json.dumps(params)[:200])

    # Drive events — flag external sharing
    results = service.activities().list(
        userKey="all", applicationName="drive",
        startTime=start, maxResults=50
    ).execute()
    drive_events = results.get("items", [])
    prom_lines.append("# HELP gworkspace_drive_events_total Drive events in last 10 min")
    prom_lines.append("# TYPE gworkspace_drive_events_total gauge")
    emit_prom("gworkspace_drive_events_total", len(drive_events))

    for event in drive_events:
        actor = event.get("actor", {}).get("email", "unknown")
        for e in event.get("events", []):
            ename = e.get("name", "")
            if ename in ("change_user_access", "change_acl_editors"):
                params = {p["name"]: p.get("value", "") for p in e.get("parameters", [])}
                target_user = params.get("target_user", "")
                if target_user and "@" in target_user:
                    domain = target_user.split("@")[1]
                    if domain not in ("yokly.gives", "agapay.gives"):
                        emit_wazuh("GWorkspace_external_share", "warning",
                                   f"External file sharing: {actor} shared with {target_user}",
                                   user=actor, target=target_user)

except Exception as e:
    print(f"WARNING: Reports API: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 2. User Directory (counts)
# ============================================================
active_users = []
try:
    dir_service = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
    all_users = []
    page_token = None
    while True:
        results = dir_service.users().list(
            customer="my_customer", maxResults=500,
            projection="basic", orderBy="email",
            pageToken=page_token
        ).execute()
        all_users.extend(results.get("users", []))
        page_token = results.get("nextPageToken")
        if not page_token:
            break

    total_users = len(all_users)
    suspended = sum(1 for u in all_users if u.get("suspended", False))
    admin_count = sum(1 for u in all_users if u.get("isAdmin", False))
    active_users = [u for u in all_users if not u.get("suspended", False)]

    prom_lines.append("# HELP gworkspace_users_total Total Google Workspace users")
    prom_lines.append("# TYPE gworkspace_users_total gauge")
    emit_prom("gworkspace_users_total", total_users)
    prom_lines.append("# HELP gworkspace_users_suspended Suspended users")
    prom_lines.append("# TYPE gworkspace_users_suspended gauge")
    emit_prom("gworkspace_users_suspended", suspended)
    prom_lines.append("# HELP gworkspace_users_admin Admin users")
    prom_lines.append("# TYPE gworkspace_users_admin gauge")
    emit_prom("gworkspace_users_admin", admin_count)
    prom_lines.append("# HELP gworkspace_users_active Active users")
    prom_lines.append("# TYPE gworkspace_users_active gauge")
    emit_prom("gworkspace_users_active", len(active_users))

except Exception as e:
    print(f"WARNING: Directory API: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 3. Drive Storage — 50GB cap monitoring
# ============================================================
try:
    reports_svc = build("admin", "reports_v1", credentials=creds, cache_discovery=False)

    over_quota_users = []
    total_storage_bytes = 0
    users_checked = 0
    users_over = 0
    users_exempt_over = 0

    prom_lines.append("# HELP gworkspace_drive_usage_bytes Per-user Drive storage usage")
    prom_lines.append("# TYPE gworkspace_drive_usage_bytes gauge")
    prom_lines.append("# HELP gworkspace_drive_over_quota User over 50GB quota (1=over)")
    prom_lines.append("# TYPE gworkspace_drive_over_quota gauge")

    for u in active_users:
        email = (u.get("primaryEmail") or "").strip().lower()
        if not email:
            continue

        usage = 0
        for delta in range(2, 9):
            d = (date.today() - timedelta(days=delta)).isoformat()
            try:
                req = reports_svc.userUsageReport().get(
                    userKey=email, date=d,
                    parameters="accounts:drive_used_quota_in_mb,accounts:gmail_used_quota_in_mb,accounts:gplus_photos_used_quota_in_mb",
                )
                resp = exec_with_retries(req)
                drive_mb = gmail_mb = photos_mb = 0
                for entry in resp.get("usageReports", []) or []:
                    for p in entry.get("parameters", []) or []:
                        name = p.get("name", "")
                        val = int(p.get("intValue", 0))
                        if name == "accounts:drive_used_quota_in_mb":
                            drive_mb = val
                        elif name == "accounts:gmail_used_quota_in_mb":
                            gmail_mb = val
                        elif name == "accounts:gplus_photos_used_quota_in_mb":
                            photos_mb = val
                usage = (drive_mb + gmail_mb + photos_mb) * 1024 * 1024
                drive_bytes = drive_mb * 1024 * 1024
                gmail_bytes = gmail_mb * 1024 * 1024
                photos_bytes = photos_mb * 1024 * 1024
                break
            except HttpError as e:
                if getattr(e.resp, "status", None) == 400:
                    continue
                break
            except Exception:
                break

        total_storage_bytes += usage
        drive_bytes = getattr(sys.modules[__name__], "drive_bytes", 0) if "drive_bytes" not in dir() else drive_bytes
        users_checked += 1
        is_exempt = email in EXEMPT
        is_over = usage > QUOTA_BYTES

        if usage > 10 * 1024**3:  # only track users > 10GB
            emit_prom("gworkspace_drive_usage_bytes", usage,
                      {"user": email, "exempt": str(is_exempt).lower()})
            emit_prom("gworkspace_drive_only_bytes", drive_bytes,
                      {"user": email})
            emit_prom("gworkspace_gmail_usage_bytes", gmail_bytes,
                      {"user": email})
            emit_prom("gworkspace_photos_usage_bytes", photos_bytes,
                      {"user": email})

        if is_over:
            emit_prom("gworkspace_drive_over_quota", 1,
                      {"user": email, "exempt": str(is_exempt).lower()})
            if is_exempt:
                users_exempt_over += 1
            else:
                users_over += 1
                over_quota_users.append((email, usage))
                emit_wazuh("GWorkspace_over_quota", "warning",
                           f"User {email} over 50GB quota: {fmt_gib(usage)} GiB used",
                           user=email, usage_gib=fmt_gib(usage), quota_gib="50.00")

    prom_lines.append("# HELP gworkspace_drive_total_bytes Total storage used across all users")
    prom_lines.append("# TYPE gworkspace_drive_total_bytes gauge")
    emit_prom("gworkspace_drive_total_bytes", total_storage_bytes)
    prom_lines.append("# HELP gworkspace_drive_users_checked Users checked for storage")
    prom_lines.append("# TYPE gworkspace_drive_users_checked gauge")
    emit_prom("gworkspace_drive_users_checked", users_checked)
    prom_lines.append("# HELP gworkspace_drive_users_over_quota Non-exempt users over 50GB")
    prom_lines.append("# TYPE gworkspace_drive_users_over_quota gauge")
    emit_prom("gworkspace_drive_users_over_quota", users_over)
    prom_lines.append("# HELP gworkspace_drive_users_exempt_over Exempt users over 50GB")
    prom_lines.append("# TYPE gworkspace_drive_users_exempt_over gauge")
    emit_prom("gworkspace_drive_users_exempt_over", users_exempt_over)
    prom_lines.append("# HELP gworkspace_drive_quota_bytes Storage quota threshold")
    prom_lines.append("# TYPE gworkspace_drive_quota_bytes gauge")
    emit_prom("gworkspace_drive_quota_bytes", QUOTA_BYTES)

    if over_quota_users:
        top5 = sorted(over_quota_users, key=lambda x: -x[1])[:5]
        summary = ", ".join(f"{e} ({fmt_gib(u)} GiB)" for e, u in top5)
        emit_wazuh("GWorkspace_quota_summary", "warning",
                   f"{users_over} non-exempt users over 50GB: {summary}",
                   count=str(users_over))

    print(f"  Storage: checked={users_checked} over={users_over} exempt_over={users_exempt_over} total={fmt_gib(total_storage_bytes)} GiB")

except Exception as e:
    print(f"WARNING: Storage check: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 4. Security Alerts (Alert Center)
# ============================================================
try:
    alerts_service = build("alertcenter", "v1beta1", credentials=creds, cache_discovery=False)
    start_time = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    results = alerts_service.alerts().list(
        filter=f'createTime >= "{start_time}"',
        pageSize=20
    ).execute()
    alerts = results.get("alerts", [])

    prom_lines.append("# HELP gworkspace_security_alerts Security alerts in last hour")
    prom_lines.append("# TYPE gworkspace_security_alerts gauge")
    emit_prom("gworkspace_security_alerts", len(alerts))

    for alert in alerts:
        alert_type = alert.get("type", "unknown")
        source = alert.get("source", "unknown")
        severity_map = {"HIGH": "critical", "MEDIUM": "warning", "LOW": "info"}
        sev = severity_map.get(alert.get("metadata", {}).get("severity", ""), "warning")
        emit_wazuh(f"GWorkspace_security_{alert_type}", sev,
                   f"Google Security Alert: {alert_type} from {source}",
                   alert_type=alert_type, alert_source=source)

except Exception as e:
    print(f"WARNING: Alert Center API: {e}", file=sys.stderr)
    errors += 1


# ============================================================
# 5. Org-wide Storage (Customer Usage Report)
# ============================================================
try:
    cust_svc = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
    for delta in range(3, 10):
        d = (date.today() - timedelta(days=delta)).isoformat()
        try:
            resp = cust_svc.customerUsageReports().get(
                date=d,
                parameters="accounts:customer_used_quota_in_mb,accounts:total_quota_in_mb,accounts:drive_used_quota_in_mb,accounts:gmail_used_quota_in_mb,accounts:gplus_photos_used_quota_in_mb,accounts:shared_drive_used_quota_in_mb,accounts:used_quota_in_mb"
            ).execute()
            org_used = org_total = org_drive = org_gmail = org_photos = org_shared = org_personal = 0
            for entry in resp.get("usageReports", []) or []:
                for p in entry.get("parameters", []) or []:
                    name = p.get("name", "")
                    val = int(p.get("intValue", 0))
                    if name == "accounts:customer_used_quota_in_mb":
                        org_used = val * 1024 * 1024
                    elif name == "accounts:total_quota_in_mb":
                        org_total = val * 1024 * 1024
                    elif name == "accounts:drive_used_quota_in_mb":
                        org_drive = val * 1024 * 1024
                    elif name == "accounts:gmail_used_quota_in_mb":
                        org_gmail = val * 1024 * 1024
                    elif name == "accounts:gplus_photos_used_quota_in_mb":
                        org_photos = val * 1024 * 1024
                    elif name == "accounts:shared_drive_used_quota_in_mb":
                        org_shared = val * 1024 * 1024
                    elif name == "accounts:used_quota_in_mb":
                        org_personal = val * 1024 * 1024

            prom_lines.append("# HELP gworkspace_org_storage_used_bytes Org total storage used (incl shared drives)")
            prom_lines.append("# TYPE gworkspace_org_storage_used_bytes gauge")
            emit_prom("gworkspace_org_storage_used_bytes", org_used)
            prom_lines.append("# HELP gworkspace_org_storage_total_bytes Org total storage pool")
            prom_lines.append("# TYPE gworkspace_org_storage_total_bytes gauge")
            emit_prom("gworkspace_org_storage_total_bytes", org_total)
            prom_lines.append("# HELP gworkspace_org_storage_used_percent Org storage usage percent")
            prom_lines.append("# TYPE gworkspace_org_storage_used_percent gauge")
            if org_total > 0:
                emit_prom("gworkspace_org_storage_used_percent", round((org_used / org_total) * 100, 1))
            prom_lines.append("# HELP gworkspace_org_storage_available_bytes Org storage remaining")
            prom_lines.append("# TYPE gworkspace_org_storage_available_bytes gauge")
            emit_prom("gworkspace_org_storage_available_bytes", org_total - org_used)
            prom_lines.append("# HELP gworkspace_org_drive_bytes Org Google Drive storage")
            prom_lines.append("# TYPE gworkspace_org_drive_bytes gauge")
            emit_prom("gworkspace_org_drive_bytes", org_drive)
            prom_lines.append("# HELP gworkspace_org_gmail_bytes Org Gmail storage")
            prom_lines.append("# TYPE gworkspace_org_gmail_bytes gauge")
            emit_prom("gworkspace_org_gmail_bytes", org_gmail)
            prom_lines.append("# HELP gworkspace_org_photos_bytes Org Google Photos storage")
            prom_lines.append("# TYPE gworkspace_org_photos_bytes gauge")
            emit_prom("gworkspace_org_photos_bytes", org_photos)
            prom_lines.append("# HELP gworkspace_org_shared_drive_bytes Org Shared Drives storage")
            prom_lines.append("# TYPE gworkspace_org_shared_drive_bytes gauge")
            emit_prom("gworkspace_org_shared_drive_bytes", org_shared)
            prom_lines.append("# HELP gworkspace_org_personal_bytes Org personal user storage")
            prom_lines.append("# TYPE gworkspace_org_personal_bytes gauge")
            emit_prom("gworkspace_org_personal_bytes", org_personal)

            print(f"  Org storage: {org_used / 1024**4:.2f} TB used of {org_total / 1024**4:.2f} TB ({(org_used/org_total*100) if org_total else 0:.1f}%)")
            print(f"    Drive: {org_drive / 1024**4:.2f} TB | Gmail: {org_gmail / 1024**3:.1f} GB | Photos: {org_photos / 1024**3:.1f} GB | Shared Drives: {org_shared / 1024**4:.2f} TB")
            break
        except Exception:
            continue

except Exception as e:
    print(f"WARNING: Customer usage: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 6. Per-Shared-Drive Storage (first page estimate + file count)
# ============================================================
try:
    DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
    drive_creds = service_account.Credentials.from_service_account_file(
        SA_KEY, scopes=DRIVE_SCOPES, subject=ADMIN_EMAIL
    )
    drive_svc = build("drive", "v3", credentials=drive_creds, cache_discovery=False)

    results = drive_svc.drives().list(pageSize=50).execute()
    shared_drives = results.get("drives", [])

    prom_lines.append("# HELP gworkspace_shared_drive_files File count per shared drive")
    prom_lines.append("# TYPE gworkspace_shared_drive_files gauge")
    prom_lines.append("# HELP gworkspace_shared_drive_size_bytes Estimated size per shared drive")
    prom_lines.append("# TYPE gworkspace_shared_drive_size_bytes gauge")

    for sd in shared_drives:
        name = sd["name"]
        drive_id = sd["id"]
        total_size = 0
        total_files = 0
        page_token = None
        # Limit to 3 pages (3000 files) to avoid rate limits
        for page in range(3):
            try:
                resp = drive_svc.files().list(
                    corpora="drive", driveId=drive_id,
                    includeItemsFromAllDrives=True, supportsAllDrives=True,
                    fields="files(size),nextPageToken",
                    pageSize=1000, q="trashed=false",
                    pageToken=page_token
                ).execute()
                for f in resp.get("files", []):
                    total_size += int(f.get("size", 0))
                    total_files += 1
                page_token = resp.get("nextPageToken")
                if not page_token:
                    break
            except Exception:
                break
            import time
            time.sleep(0.5)  # rate limit protection

        safe_name = name.replace('"', '').replace("'", "")
        emit_prom("gworkspace_shared_drive_size_bytes", total_size, {"drive": safe_name})
        emit_prom("gworkspace_shared_drive_files", total_files, {"drive": safe_name})

    prom_lines.append("# HELP gworkspace_shared_drives_total Total shared drives count")
    prom_lines.append("# TYPE gworkspace_shared_drives_total gauge")
    emit_prom("gworkspace_shared_drives_total", len(shared_drives))

    print(f"  Shared drives: {len(shared_drives)} drives scanned")

except Exception as e:
    print(f"WARNING: Shared drives: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# Write outputs
# ============================================================
prom_lines.append("# HELP gworkspace_collector_up Google Workspace collector status (1=ok)")
prom_lines.append("# TYPE gworkspace_collector_up gauge")
emit_prom("gworkspace_collector_up", 1 if errors == 0 else 0)
prom_lines.append("# HELP gworkspace_collector_errors Collector error count")
prom_lines.append("# TYPE gworkspace_collector_errors gauge")
emit_prom("gworkspace_collector_errors", errors)

PROMFILE.write_text("\n".join(prom_lines) + "\n")

if wazuh_events:
    with open(LOGFILE, "a") as f:
        for e in wazuh_events:
            f.write(e + "\n")

print(f"OK: {len(prom_lines)} prom metrics, {len(wazuh_events)} wazuh events, {errors} errors")
