#!/usr/bin/env python3
"""
employee-gworkspace-reconcile.py
Compare employees.json roster against live Google Workspace user list.
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
                                fields="nextPageToken,users(primaryEmail,suspended,isAdmin,name)")
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

orphaned = []
for email, u in gw_active.items():
    if email not in roster_all:
        orphaned.append({
            "email": email, "name": u.get("name", {}).get("fullName", ""),
            "is_admin": u.get("isAdmin", False), "authorized": email in authorized_admins,
        })

missing_gw = []
for email in roster_emails:
    if email not in gw_all:
        emp = roster_all[email]
        missing_gw.append({"email": email, "name": emp.get("name",""), "department": emp.get("department","")})

suspended_active = []
for email in roster_emails:
    if email in gw_suspended:
        emp = roster_all[email]
        suspended_active.append({"email": email, "name": emp.get("name",""), "department": emp.get("department","")})

admin_unregistered = []
for email, u in gw_admin.items():
    if email not in roster_all:
        admin_unregistered.append({
            "email": email, "name": u.get("name", {}).get("fullName", ""),
            "authorized": email in authorized_admins,
        })

unauthorized_admins = [a for a in admin_unregistered if not a["authorized"]]

# ── Emit Prometheus metrics ────────────────────────────────────────────
emit_prom("employee_reconcile_collector_up", 1, help_text="1 if collector ran successfully")
emit_prom("employee_reconcile_employees_total", len(employees), help_text="Total employees in roster")
emit_prom("employee_reconcile_active_employees", len(roster_emails), help_text="Active employees in roster")
emit_prom("employee_reconcile_gw_users_total", len(gw_users), help_text="Total Google Workspace users")
emit_prom("employee_reconcile_gw_active_total", len(gw_active), help_text="Active (non-suspended) GW users")
emit_prom("employee_reconcile_orphaned_accounts", len(orphaned), help_text="GW accounts with no employee record")
emit_prom("employee_reconcile_missing_gw_accounts", len(missing_gw), help_text="Active employees with no GW account")
emit_prom("employee_reconcile_suspended_active_employees", len(suspended_active), help_text="Active employees whose GW account is suspended")
emit_prom("employee_reconcile_admin_unregistered", len(unauthorized_admins), help_text="GW admin accounts not in roster and not authorized")
emit_prom("employee_reconcile_authorized_admins_total", len(authorized_admins), help_text="Total authorized GW super-admin accounts")
emit_prom("employee_reconcile_last_run_timestamp", int(datetime.datetime.now().timestamp()), help_text="Unix timestamp of last successful run")

prom.append("# HELP employee_reconcile_orphan_info 1 for each orphaned GW account")
prom.append("# TYPE employee_reconcile_orphan_info gauge")
for o in orphaned:
    lbl = f'email="{o["email"]}",name="{o["name"]}",is_admin="{str(o["is_admin"]).lower()}",authorized="{str(o["authorized"]).lower()}"'
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
    f"{len(orphaned)} orphaned, {len(missing_gw)} missing, "
    f"{len(suspended_active)} suspended-active, {len(unauthorized_admins)} unauthorized-admin",
    employees_active=len(roster_emails), gw_users_active=len(gw_active),
    orphaned_count=len(orphaned), missing_count=len(missing_gw),
    suspended_active_count=len(suspended_active), admin_unregistered_count=len(unauthorized_admins),
)

for o in orphaned:
    if o["is_admin"]:
        if o["authorized"]:
            emit_wazuh("EmployeeOrphanedGWAccount", "info",
                f"Authorized GW admin {o['email']} not in employee roster — verify if intentional",
                email=o["email"], full_name=o["name"], is_admin="true", authorized="true")
        else:
            emit_wazuh("EmployeeOrphanedGWAccount", "critical",
                f"CRITICAL: Orphaned GW ADMIN account: {o['email']} — unauthorized admin access",
                email=o["email"], full_name=o["name"], is_admin="true", authorized="false")
    else:
        emit_wazuh("EmployeeOrphanedGWAccount", "warning",
            f"GW account {o['email']} has no employee record — possible orphaned account",
            email=o["email"], full_name=o["name"], is_admin="false", authorized="false")

for a in admin_unregistered:
    if not a["authorized"]:
        emit_wazuh("EmployeeAdminUnregistered", "critical",
            f"GW admin account {a['email']} is NOT in employee roster — unauthorized admin",
            email=a["email"], full_name=a["name"])

for s in suspended_active:
    emit_wazuh("EmployeeSuspendedActive", "warning",
        f"Employee {s['email']} is active in roster but GW account is suspended",
        email=s["email"], name=s["name"], department=s["department"])

for m in missing_gw:
    emit_wazuh("EmployeeMissingGWAccount", "info",
        f"Employee {m['email']} in roster has no Google Workspace account",
        email=m["email"], name=m["name"], department=m["department"])

# ── Write output ────────────────────────────────────────────────────────
PROMFILE.write_text("\n".join(prom) + "\n")
with LOGFILE.open("a") as f:
    f.write("\n".join(wazuh) + "\n")

print(f"Reconcile OK: {len(roster_emails)} employees / {len(gw_active)} GW active / "
      f"{len(orphaned)} orphaned / {len(missing_gw)} missing GW / "
      f"{len(unauthorized_admins)} unauthorized-admin / "
      f"{len(authorized_admins)} authorized admins on file")
