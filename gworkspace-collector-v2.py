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
    "https://www.googleapis.com/auth/admin.directory.group.member.readonly",
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
# 3. Drive Storage — per-user (50GB cap + Drive/Gmail split)
# ============================================================
org_drive_bytes = 0
org_gmail_bytes = 0
org_photos_bytes_total = 0
org_quota_bytes_total = 0

try:
    reports_svc = build("admin", "reports_v1", credentials=creds, cache_discovery=False)

    over_quota_users = []
    total_storage_bytes = 0
    users_checked = 0
    users_over = 0
    users_exempt_over = 0

    prom_lines.append("# HELP gworkspace_drive_usage_bytes Per-user total storage (Drive + Gmail)")
    prom_lines.append("# TYPE gworkspace_drive_usage_bytes gauge")
    prom_lines.append("# HELP gworkspace_drive_only_bytes Per-user Drive storage (excl. Gmail and Photos)")
    prom_lines.append("# TYPE gworkspace_drive_only_bytes gauge")
    prom_lines.append("# HELP gworkspace_gmail_usage_bytes Per-user Gmail storage")
    prom_lines.append("# TYPE gworkspace_gmail_usage_bytes gauge")
    prom_lines.append("# HELP gworkspace_photos_usage_bytes Per-user Google Photos storage")
    prom_lines.append("# TYPE gworkspace_photos_usage_bytes gauge")
    prom_lines.append("# HELP gworkspace_drive_over_quota User over 50GB quota (1=over)")
    prom_lines.append("# TYPE gworkspace_drive_over_quota gauge")

    for u in active_users:
        email = (u.get("primaryEmail") or "").strip().lower()
        if not email:
            continue

        usage = 0
        drive_bytes_user = 0
        gmail_bytes_user = 0
        photos_bytes_user = 0
        quota_bytes_user = 0

        for delta in range(2, 9):
            d = (date.today() - timedelta(days=delta)).isoformat()
            try:
                req = reports_svc.userUsageReport().get(
                    userKey=email, date=d,
                    parameters="accounts:used_quota_in_mb,accounts:drive_used_quota_in_mb,accounts:gmail_used_quota_in_mb,accounts:gplus_photos_used_quota_in_mb,accounts:total_quota_in_mb",
                )
                resp = exec_with_retries(req)
                for entry in resp.get("usageReports", []) or []:
                    for p in entry.get("parameters", []) or []:
                        n = p.get("name")
                        v = int(p.get("intValue", 0) or 0)
                        if n == "accounts:used_quota_in_mb":
                            usage = v * 1024 * 1024
                        elif n == "accounts:drive_used_quota_in_mb":
                            drive_bytes_user = v * 1024 * 1024
                        elif n == "accounts:gmail_used_quota_in_mb":
                            gmail_bytes_user = v * 1024 * 1024
                        elif n == "accounts:gplus_photos_used_quota_in_mb":
                            photos_bytes_user = v * 1024 * 1024
                        elif n == "accounts:total_quota_in_mb":
                            quota_bytes_user = v * 1024 * 1024
                break
            except HttpError as e:
                if getattr(e.resp, "status", None) == 400:
                    continue
                break
            except Exception:
                break

        total_storage_bytes += usage
        org_drive_bytes += drive_bytes_user
        org_gmail_bytes += gmail_bytes_user
        org_photos_bytes_total += photos_bytes_user
        org_quota_bytes_total += quota_bytes_user
        users_checked += 1
        is_exempt = email in EXEMPT
        is_over = usage > QUOTA_BYTES

        if usage > 10 * 1024**3:
            emit_prom("gworkspace_drive_usage_bytes", usage,
                      {"user": email, "exempt": str(is_exempt).lower()})
        if drive_bytes_user > 5 * 1024**3:
            emit_prom("gworkspace_drive_only_bytes", drive_bytes_user,
                      {"user": email, "exempt": str(is_exempt).lower()})
        if gmail_bytes_user > 500 * 1024**2:
            emit_prom("gworkspace_gmail_usage_bytes", gmail_bytes_user,
                      {"user": email})
        if photos_bytes_user > 500 * 1024**2:
            emit_prom("gworkspace_photos_usage_bytes", photos_bytes_user,
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

    print(f"  Storage: checked={users_checked} over={users_over} exempt_over={users_exempt_over} total={fmt_gib(total_storage_bytes)} GiB drive={fmt_gib(org_drive_bytes)} GiB gmail={fmt_gib(org_gmail_bytes)} GiB photos={fmt_gib(org_photos_bytes_total)} GiB quota={fmt_gib(org_quota_bytes_total)} GiB")

except Exception as e:
    print(f"WARNING: Storage check: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 3b. Shared Drives — enumerate, file count, sampled size
# ============================================================
org_shared_bytes = 0

try:
    drive_svc = build("drive", "v3", credentials=creds, cache_discovery=False)

    all_drives = []
    pt = None
    while True:
        resp = drive_svc.drives().list(
            pageSize=100, pageToken=pt,
            fields="nextPageToken,drives(id,name)"
        ).execute()
        all_drives.extend(resp.get("drives", []))
        pt = resp.get("nextPageToken")
        if not pt:
            break

    prom_lines.append("# HELP gworkspace_shared_drives_total Total shared drives in org")
    prom_lines.append("# TYPE gworkspace_shared_drives_total gauge")
    emit_prom("gworkspace_shared_drives_total", len(all_drives))

    prom_lines.append("# HELP gworkspace_shared_drive_size_bytes Shared drive storage (sampled, may undercount large drives)")
    prom_lines.append("# TYPE gworkspace_shared_drive_size_bytes gauge")
    prom_lines.append("# HELP gworkspace_shared_drive_files Shared drive file count")
    prom_lines.append("# TYPE gworkspace_shared_drive_files gauge")

    for drv in all_drives:
        drive_id = drv.get("id")
        drive_name = drv.get("name", drive_id)
        size_bytes = 0
        file_count = 0
        pt2 = None
        pages = 0
        while pages < 50:  # cap at ~50k files per drive
            try:
                files_resp = drive_svc.files().list(
                    driveId=drive_id,
                    includeItemsFromAllDrives=True,
                    supportsAllDrives=True,
                    corpora="drive",
                    fields="nextPageToken,files(quotaBytesUsed)",
                    pageSize=1000,
                    pageToken=pt2
                ).execute()
            except HttpError:
                break
            for f in files_resp.get("files", []):
                file_count += 1
                size_bytes += int(f.get("quotaBytesUsed", 0) or 0)
            pt2 = files_resp.get("nextPageToken")
            pages += 1
            if not pt2:
                break

        org_shared_bytes += size_bytes
        emit_prom("gworkspace_shared_drive_size_bytes", size_bytes, {"drive": drive_name})
        emit_prom("gworkspace_shared_drive_files", file_count, {"drive": drive_name})

    print(f"  Shared drives: count={len(all_drives)} total_size={fmt_gib(org_shared_bytes)} GiB")

except Exception as e:
    print(f"WARNING: Shared drives: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 3c. Org-level Storage Totals
# ============================================================
try:
    org_total_bytes = 0
    org_used_bytes = 0

    # All org totals computed from per-user accumulation above
    org_used_bytes = total_storage_bytes
    org_total_bytes = org_quota_bytes_total  # sum of per-user total_quota_in_mb

    org_photos_bytes = org_photos_bytes_total
    org_available_bytes = max(0, org_total_bytes - org_used_bytes)
    org_used_pct = round(org_used_bytes / org_total_bytes * 100, 2) if org_total_bytes > 0 else 0.0

    prom_lines.append("# HELP gworkspace_org_storage_total_bytes Org total pooled storage quota")
    prom_lines.append("# TYPE gworkspace_org_storage_total_bytes gauge")
    emit_prom("gworkspace_org_storage_total_bytes", org_total_bytes)
    prom_lines.append("# HELP gworkspace_org_storage_used_bytes Org total used storage")
    prom_lines.append("# TYPE gworkspace_org_storage_used_bytes gauge")
    emit_prom("gworkspace_org_storage_used_bytes", org_used_bytes)
    prom_lines.append("# HELP gworkspace_org_storage_available_bytes Org remaining storage")
    prom_lines.append("# TYPE gworkspace_org_storage_available_bytes gauge")
    emit_prom("gworkspace_org_storage_available_bytes", org_available_bytes)
    prom_lines.append("# HELP gworkspace_org_storage_used_percent Org storage used percentage")
    prom_lines.append("# TYPE gworkspace_org_storage_used_percent gauge")
    emit_prom("gworkspace_org_storage_used_percent", org_used_pct)
    prom_lines.append("# HELP gworkspace_org_drive_bytes Org personal Drive storage (Drive+Photos per user)")
    prom_lines.append("# TYPE gworkspace_org_drive_bytes gauge")
    emit_prom("gworkspace_org_drive_bytes", org_drive_bytes)
    prom_lines.append("# HELP gworkspace_org_gmail_bytes Org total Gmail storage")
    prom_lines.append("# TYPE gworkspace_org_gmail_bytes gauge")
    emit_prom("gworkspace_org_gmail_bytes", org_gmail_bytes)
    prom_lines.append("# HELP gworkspace_org_photos_bytes Org Photos storage (residual)")
    prom_lines.append("# TYPE gworkspace_org_photos_bytes gauge")
    emit_prom("gworkspace_org_photos_bytes", org_photos_bytes)
    prom_lines.append("# HELP gworkspace_org_shared_drive_bytes Org shared drive storage (sampled)")
    prom_lines.append("# TYPE gworkspace_org_shared_drive_bytes gauge")
    emit_prom("gworkspace_org_shared_drive_bytes", org_shared_bytes)
    prom_lines.append("# HELP gworkspace_org_personal_bytes Org personal Drive storage")
    prom_lines.append("# TYPE gworkspace_org_personal_bytes gauge")
    emit_prom("gworkspace_org_personal_bytes", org_drive_bytes)

    print(f"  Org storage: total={fmt_gib(org_total_bytes)} GiB used={fmt_gib(org_used_bytes)} GiB ({org_used_pct}%) avail={fmt_gib(org_available_bytes)} GiB")

except Exception as e:
    print(f"WARNING: Org storage totals: {e}", file=sys.stderr)
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
# 5. External Sharing Policy Audit (Group-based enforcement)
# Enforcement model:
#   - Root of domain (Agape Global Services): Sharing = ON (default ALLOWED)
#   - Restrictive Drive sharing policy applied to 4 Google Groups:
#       hrou, itdevou, marketingou, trainingou → members are BLOCKED
#   - /Yokly/SHARED-DRIVES-EXTERNAL OU override: ON (delegates ALLOWED)
# Priority: OU override > Group membership > Root default
# Categories: BLOCKED / EXCEPTION / UNRESTRICTED
# ============================================================
RESTRICTED_GROUPS = [
    "hrou@yokly.gives",
    "itdevou@yokly.gives",
    "marketingou@yokly.gives",
    "trainingou@yokly.gives",
]
EXCEPTION_OUS = ("/Yokly/SHARED-DRIVES-EXTERNAL",)

# Service accounts and shared/bot mailboxes — excluded from UNRESTRICTED alerts
EXTSHARE_EXCLUDE_PATTERNS = (".iam.gserviceaccount.com",)
EXTSHARE_EXCLUDE_EMAILS = {
    "billing@yokly.gives",
    "it_dept@yokly.gives",
    "it_dept@agapay.gives",
    "clientjourney.ai@yokly.gives",
    "hradvisor.ai@yokly.gives",
    "salesmarketing.ai@yokly.gives",
    "agapay_socials@agapay.gives",
    "yokly@yokly.gives",
    "eve@yoklygives.com",
}
# Privileged/admin users legitimately exempt from restriction
EXTSHARE_EXEMPT = EXEMPT  # reuse 50GB exempt list (same privileged users)

def _extshare_excluded(email):
    if email in EXTSHARE_EXCLUDE_EMAILS or email in EXTSHARE_EXEMPT:
        return True
    return any(email.endswith(p) for p in EXTSHARE_EXCLUDE_PATTERNS)

try:
    if not dir_service:
        dir_service = build("admin", "directory_v1", credentials=creds, cache_discovery=False)

    # Collect members of all restrictive groups → BLOCKED set
    blocked_members = set()
    for grp in RESTRICTED_GROUPS:
        page_token = None
        while True:
            resp = dir_service.members().list(
                groupKey=grp, maxResults=200, pageToken=page_token
            ).execute()
            for m in resp.get("members", []):
                email = (m.get("email") or "").strip().lower()
                if email:
                    blocked_members.add(email)
            page_token = resp.get("nextPageToken")
            if not page_token:
                break

    # Classify active users
    # Priority: OU override (EXCEPTION) > Group membership (BLOCKED) > otherwise UNRESTRICTED
    blocked_users = []
    exception_users = []
    unrestricted_users = []

    for u in active_users:
        email = (u.get("primaryEmail") or "").strip().lower()
        ou = u.get("orgUnitPath", "/")
        if not email:
            continue
        if ou in EXCEPTION_OUS:
            exception_users.append((email, ou))
        elif email in blocked_members:
            blocked_users.append((email, ou))
        else:
            if not _extshare_excluded(email):
                unrestricted_users.append((email, ou))

    prom_lines.append("# HELP gworkspace_extshare_blocked_users Active users in restrictive group (compliant)")
    prom_lines.append("# TYPE gworkspace_extshare_blocked_users gauge")
    emit_prom("gworkspace_extshare_blocked_users", len(blocked_users))

    prom_lines.append("# HELP gworkspace_extshare_exception_users Active users in /Yokly/SHARED-DRIVES-EXTERNAL OU (authorized via OU placement)")
    prom_lines.append("# TYPE gworkspace_extshare_exception_users gauge")
    emit_prom("gworkspace_extshare_exception_users", len(exception_users))

    prom_lines.append("# HELP gworkspace_extshare_unrestricted_users Active users with external sharing allowed by default (NOT in restrictive group, not exempt)")
    prom_lines.append("# TYPE gworkspace_extshare_unrestricted_users gauge")
    emit_prom("gworkspace_extshare_unrestricted_users", len(unrestricted_users))

    prom_lines.append("# HELP gworkspace_extshare_restrictive_groups_configured Count of restrictive groups configured")
    prom_lines.append("# TYPE gworkspace_extshare_restrictive_groups_configured gauge")
    emit_prom("gworkspace_extshare_restrictive_groups_configured", len(RESTRICTED_GROUPS))

    # Per-user labels (for tables + drill-down)
    prom_lines.append("# HELP gworkspace_extshare_user_category Per-user external sharing category (1 = in this category)")
    prom_lines.append("# TYPE gworkspace_extshare_user_category gauge")
    for email, ou in blocked_users:
        emit_prom("gworkspace_extshare_user_category", 1,
                  {"user": email, "category": "blocked", "ou": ou})
    for email, ou in exception_users:
        emit_prom("gworkspace_extshare_user_category", 1,
                  {"user": email, "category": "exception", "ou": ou})
    for email, ou in unrestricted_users:
        emit_prom("gworkspace_extshare_user_category", 1,
                  {"user": email, "category": "unrestricted", "ou": ou})

    # Wazuh alerts
    if unrestricted_users:
        emit_wazuh("GWorkspace_extshare_unrestricted", "warning",
                   f"{len(unrestricted_users)} active users NOT in restrictive group — can still share externally",
                   count=str(len(unrestricted_users)),
                   users=",".join(sorted(e for e, _ in unrestricted_users))[:500])

    if exception_users:
        emit_wazuh("GWorkspace_extshare_exception_present", "info",
                   f"{len(exception_users)} user(s) in SHARED-DRIVES-EXTERNAL OU (authorized external sharing)",
                   count=str(len(exception_users)),
                   users=",".join(sorted(e for e, _ in exception_users))[:500])

    print(f"  ExtShare Audit: blocked={len(blocked_users)} "
          f"exception={len(exception_users)} "
          f"unrestricted={len(unrestricted_users)}")

except Exception as e:
    print(f"WARNING: ExtShare audit: {e}", file=sys.stderr)
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
