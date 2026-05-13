#!/usr/bin/env python3
"""
employee-gworkspace-reconcile.py
Compare employees.json roster against live Google Workspace user list.
Classifies GW accounts into:
  - Matched employee accounts
  - Approved service / shared / system accounts
  - Authorized admin accounts
  - True orphaned accounts (none of the above)
  - Missing GW accounts (active employee with no GW account)

Emits:
  - /opt/monitoring/textfile_collector/employee_reconcile.prom
  - /var/log/employee-gworkspace-wazuh.log  (one JSON line per finding)
"""
import json, os, sys, datetime
from pathlib import Path

SA_KEY       = os.environ.get("SA_KEY",    "/keys/gam-project-gf5mq-97886701cbdd.json")
ADMIN        = os.environ.get("ADMIN_EMAIL","brian.monte@yokly.gives")
ROSTER       = Path(os.environ.get("ROSTER_FILE",  "/opt/monitoring/data/employees.json"))
AUTH_ADMINS  = Path(os.environ.get("AUTH_ADMINS_FILE", "/opt/monitoring/data/authorized_admins.json"))
SVC_ACCOUNTS = Path(os.environ.get("SVC_ACCOUNTS_FILE", "/opt/monitoring/approved_service_accounts.json"))
PROMFILE     = Path(os.environ.get("PROMFILE", "/opt/monitoring/textfile_collector/employee_reconcile.prom"))
LOGFILE      = Path(os.environ.get("LOGFILE",  "/var/log/employee-gworkspace-wazuh.log"))

ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
prom  = []
wazuh = []

def emit_prom(name, value, labels=None, help_text="", type_hint="gauge"):
    if help_text:
        prom.append(f"# HELP {name} {help_text}")
    if type_hint:
        prom.append(f"# TYPE {name} {type_hint}")
    if labels:
        lbl = ",".join(f'{k}="{v}"' for k, v in labels.items())
        prom.append(f"{name}{{{lbl}}} {value}")
    else:
        prom.append(f"{name} {value}")

def emit_wazuh(alertname, severity, summary, **extra):
    event = {"timestamp": ts, "source": "employee_reconcile",
             "alertname": alertname, "severity": severity, "summary": summary}
    event.update(extra)
    wazuh.append(json.dumps(event))

def fail(msg):
    emit_prom("employee_reconcile_collector_up", 0, help_text="1 if collector ran successfully")
    emit_wazuh("EmployeeReconcileCollectorDown", "critical", msg)
    PROMFILE.write_text("\n".join(prom) + "\n")
    with LOGFILE.open("a") as f:
        f.write("\n".join(wazuh) + "\n")
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

# ── Load employee roster ────────────────────────────────────────────────
if not ROSTER.exists():
    fail(f"Employee roster not found: {ROSTER}")
try:
    employees = json.loads(ROSTER.read_text())
except Exception as e:
    fail(f"Cannot parse employee roster: {e}")

roster_emails = {e["email"].lower() for e in employees if e.get("status") == "active"}
roster_all    = {e["email"].lower(): e for e in employees}

# ── Load authorized admins ──────────────────────────────────────────────
authorized_admins = {}
if AUTH_ADMINS.exists():
    try:
        for a in json.loads(AUTH_ADMINS.read_text()):
            authorized_admins[a["email"].lower()] = a
    except Exception as e:
        print(f"WARN: could not load authorized_admins.json: {e}", file=sys.stderr)

# ── Load approved service accounts ─────────────────────────────────────
approved_svc = {}
if SVC_ACCOUNTS.exists():
    try:
        for sa in json.loads(SVC_ACCOUNTS.read_text()):
            approved_svc[sa["email"].lower().strip()] = sa
    except Exception as e:
        print(f"WARN: could not load approved_service_accounts.json: {e}", file=sys.stderr)
else:
    print(f"WARN: approved_service_accounts.json not found at {SVC_ACCOUNTS}", file=sys.stderr)

# ── Fetch live GWorkspace users ─────────────────────────────────────────
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
except ImportError:
    fail("google-api-python-client not installed")

try:
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY,
        scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
        subject=ADMIN
    )
except Exception as e:
    fail(f"Auth failed: {e}")

try:
    svc = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
    gw_users = []
    request = svc.users().list(customer="my_customer", maxResults=500, orderBy="email",
                                fields="nextPageToken,users(primaryEmail,suspended,isAdmin,name,orgUnitPath,lastLoginTime,creationTime)")
    while request:
        resp = request.execute()
        gw_users.extend(resp.get("users", []))
        request = svc.users().list_next(request, resp)
except Exception as e:
    fail(f"GWorkspace API error: {e}")

# ── Reconcile ──────────────────────────────────────────────────────────
gw_active    = {u["primaryEmail"].lower(): u for u in gw_users if not u.get("suspended", False)}
gw_suspended = {u["primaryEmail"].lower(): u for u in gw_users if u.get("suspended", False)}
gw_admin     = {u["primaryEmail"].lower(): u for u in gw_users if u.get("isAdmin", False)}
gw_all       = {u["primaryEmail"].lower(): u for u in gw_users}

# Classify each active GW account
service_account_list = []   # approved service/shared/system accounts
true_orphans         = []   # not in employee roster, not in svc accounts, not in auth admins

for email, u in gw_active.items():
    name = u.get("name", {}).get("fullName", "")
    is_admin = u.get("isAdmin", False)

    if email in roster_all:
        pass  # matched to employee record (active or inactive)
    elif email in approved_svc:
        sa = approved_svc[email]
        service_account_list.append({
            "email":   email,
            "name":    name,
            "type":    sa.get("type", "service_account"),
            "label":   sa.get("label", "Service Account"),
            "owner":   sa.get("owner", "IT"),
            "status":  sa.get("status", "approved"),
            "is_admin": is_admin,
        })
    elif email in authorized_admins:
        pass  # authorized admin — handled in admin section
    else:
        true_orphans.append({
            "email":    email,
            "name":     name,
            "is_admin": is_admin,
            "authorized": email in authorized_admins,
        })

# Active employees missing a GW account
missing_gw = []
for email in roster_emails:
    if email not in gw_all:
        emp = roster_all[email]
        missing_gw.append({"email": email, "name": emp.get("name",""), "department": emp.get("department","")})

# Active employees whose GW account is suspended
suspended_active = []
for email in roster_emails:
    if email in gw_suspended:
        emp = roster_all[email]
        suspended_active.append({"email": email, "name": emp.get("name",""), "department": emp.get("department","")})

# Admin classification
unauthorized_admins   = []  # admin, not in authorized_admins, not a service account
service_account_admins = []  # admin, in approved_svc but not in authorized_admins

for email, u in gw_admin.items():
    if email in authorized_admins:
        continue  # explicitly authorized
    name = u.get("name", {}).get("fullName", "")
    if email in approved_svc:
        sa = approved_svc[email]
        service_account_admins.append({
            "email": email,
            "name":  name,
            "type":  sa.get("type", "service_account"),
            "label": sa.get("label", "Service Account"),
        })
    else:
        unauthorized_admins.append({
            "email": email,
            "name":  name,
            "in_roster": email in roster_all,
        })

# ── Emit Prometheus metrics ────────────────────────────────────────────
emit_prom("employee_reconcile_collector_up", 1, help_text="1 if collector ran successfully")
emit_prom("employee_reconcile_employees_total", len(employees), help_text="Total employees in roster")
emit_prom("employee_reconcile_active_employees", len(roster_emails), help_text="Active employees in roster")
emit_prom("employee_reconcile_gw_users_total", len(gw_users), help_text="Total Google Workspace users")
emit_prom("employee_reconcile_gw_active_total", len(gw_active), help_text="Active (non-suspended) GW users")
emit_prom("employee_reconcile_approved_service_accounts_total", len(service_account_list),
          help_text="Approved service/shared/system GW accounts (excluded from orphan count)")
emit_prom("employee_reconcile_service_account_admin_total", len(service_account_admins),
          help_text="Approved service accounts with GW admin privileges — review if intentional")
# true orphaned = accounts not matched to any known category
emit_prom("employee_reconcile_true_orphaned_accounts", len(true_orphans),
          help_text="GW accounts with no employee record, not a service account, not an authorized admin")
# backward-compat alias — same value as true_orphaned_accounts
emit_prom("employee_reconcile_orphaned_accounts", len(true_orphans),
          help_text="GW accounts with no employee record (true orphans, service accounts excluded)")
emit_prom("employee_reconcile_missing_gw_accounts", len(missing_gw),
          help_text="Active employees with no GW account")
emit_prom("employee_reconcile_suspended_active_employees", len(suspended_active),
          help_text="Active employees whose GW account is suspended")
emit_prom("employee_reconcile_unauthorized_admins_total", len(unauthorized_admins),
          help_text="GW admin accounts not in authorized admin list and not an approved service account")
# backward-compat alias
emit_prom("employee_reconcile_admin_unregistered", len(unauthorized_admins),
          help_text="GW admin accounts not authorized (alias for unauthorized_admins_total)")
emit_prom("employee_reconcile_authorized_admins_total", len(authorized_admins),
          help_text="Total authorized GW super-admin accounts")
emit_prom("employee_reconcile_last_run_timestamp",
          int(datetime.datetime.now().timestamp()),
          help_text="Unix timestamp of last successful run")

# Service account info metrics
prom.append("# HELP employee_reconcile_service_account_info 1 for each approved service/shared/system GW account")
prom.append("# TYPE employee_reconcile_service_account_info gauge")
for sa in service_account_list:
    lbl = (f'email="{sa["email"]}",type="{sa["type"]}",label="{sa["label"]}",'
           f'owner="{sa["owner"]}",status="{sa["status"]}",is_admin="{str(sa["is_admin"]).lower()}"')
    prom.append(f"employee_reconcile_service_account_info{{{lbl}}} 1")

# Service account admin info
prom.append("# HELP employee_reconcile_service_account_admin_info 1 for each service account with admin privileges")
prom.append("# TYPE employee_reconcile_service_account_admin_info gauge")
for sa in service_account_admins:
    lbl = f'email="{sa["email"]}",type="{sa["type"]}",label="{sa["label"]}"'
    prom.append(f"employee_reconcile_service_account_admin_info{{{lbl}}} 1")

# True orphan info (+ backward-compat alias)
prom.append("# HELP employee_reconcile_true_orphan_info 1 for each true orphaned GW account")
prom.append("# TYPE employee_reconcile_true_orphan_info gauge")
for o in true_orphans:
    lbl = (f'email="{o["email"]}",name="{o["name"]}",'
           f'is_admin="{str(o["is_admin"]).lower()}",authorized="{str(o["authorized"]).lower()}"')
    prom.append(f"employee_reconcile_true_orphan_info{{{lbl}}} 1")

prom.append("# HELP employee_reconcile_orphan_info 1 for each orphaned GW account (alias for true_orphan_info)")
prom.append("# TYPE employee_reconcile_orphan_info gauge")
for o in true_orphans:
    lbl = (f'email="{o["email"]}",name="{o["name"]}",'
           f'is_admin="{str(o["is_admin"]).lower()}",authorized="{str(o["authorized"]).lower()}"')
    prom.append(f"employee_reconcile_orphan_info{{{lbl}}} 1")

prom.append("# HELP employee_reconcile_authorized_admin_info 1 for each authorized GW super-admin")
prom.append("# TYPE employee_reconcile_authorized_admin_info gauge")
for email, a in authorized_admins.items():
    lbl = f'email="{email}",name="{a.get("name","")}",role="{a.get("role","")}"'
    prom.append(f"employee_reconcile_authorized_admin_info{{{lbl}}} 1")

prom.append("# HELP employee_reconcile_missing_info 1 for each employee missing a GW account")
prom.append("# TYPE employee_reconcile_missing_info gauge")
for m in missing_gw:
    lbl = f'email="{m["email"]}",name="{m["name"]}",department="{m["department"]}"'
    prom.append(f"employee_reconcile_missing_info{{{lbl}}} 1")

# ── Emit Wazuh events ──────────────────────────────────────────────────
emit_wazuh("EmployeeReconcileSummary", "info",
    f"Reconcile: {len(roster_emails)} employees, {len(gw_active)} GW active, "
    f"{len(true_orphans)} true-orphaned, {len(service_account_list)} service-accounts, "
    f"{len(missing_gw)} missing, {len(suspended_active)} suspended-active, "
    f"{len(unauthorized_admins)} unauthorized-admin, {len(service_account_admins)} svc-acct-admin",
    employees_active=len(roster_emails),
    gw_users_active=len(gw_active),
    true_orphaned_count=len(true_orphans),
    service_accounts_count=len(service_account_list),
    missing_count=len(missing_gw),
    suspended_active_count=len(suspended_active),
    unauthorized_admin_count=len(unauthorized_admins),
    service_account_admin_count=len(service_account_admins),
)

# True orphaned account alerts (service accounts excluded)
for o in true_orphans:
    if o["is_admin"]:
        emit_wazuh("EmployeeOrphanedGWAccount", "critical",
            f"CRITICAL: Orphaned GW ADMIN account: {o['email']} — not in roster, not a service account, unauthorized admin access",
            email=o["email"], full_name=o["name"], is_admin="true", authorized="false")
    else:
        emit_wazuh("EmployeeOrphanedGWAccount", "warning",
            f"GW account {o['email']} has no employee record and is not an approved service account — possible orphaned account",
            email=o["email"], full_name=o["name"], is_admin="false", authorized="false")

# Unauthorized admins (not in authorized_admins, not a service account)
for a in unauthorized_admins:
    emit_wazuh("EmployeeAdminUnregistered", "critical",
        f"GW admin account {a['email']} is NOT authorized — not in employee roster and not an approved service account",
        email=a["email"], full_name=a["name"], in_roster=str(a["in_roster"]).lower())

# Service accounts with admin privileges
for sa in service_account_admins:
    emit_wazuh("ServiceAccountAdminReview", "warning",
        f"Service account {sa['email']} ({sa['label']}) has GW admin privileges — verify if intentional",
        email=sa["email"], type=sa["type"], label=sa["label"])

# Suspended active employees
for s in suspended_active:
    emit_wazuh("EmployeeSuspendedActive", "warning",
        f"Employee {s['email']} is active in roster but GW account is suspended",
        email=s["email"], name=s["name"], department=s["department"])

# Missing GW accounts
for m in missing_gw:
    emit_wazuh("EmployeeMissingGWAccount", "info",
        f"Employee {m['email']} in roster has no Google Workspace account",
        email=m["email"], name=m["name"], department=m["department"])

# ── Write output ────────────────────────────────────────────────────────
PROMFILE.write_text("\n".join(prom) + "\n")
with LOGFILE.open("a") as f:
    f.write("\n".join(wazuh) + "\n")

print(f"Reconcile OK: {len(roster_emails)} employees / {len(gw_active)} GW active / "
      f"{len(true_orphans)} true-orphaned / {len(service_account_list)} service-accounts / "
      f"{len(missing_gw)} missing GW / {len(unauthorized_admins)} unauthorized-admin / "
      f"{len(service_account_admins)} svc-acct-admin / {len(authorized_admins)} authorized admins on file")
