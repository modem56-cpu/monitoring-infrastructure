#!/usr/bin/env bash
# deploy-employee-reconcile.sh
# Employee ↔ Google Workspace reconciliation:
#   - Compares employees.json roster against live GWorkspace user list
#   - Flags orphaned GW accounts (no employee record — offboarding risk)
#   - Flags missing GW accounts (employee with no login)
#   - Flags suspended GW accounts for active employees
#   - Flags admin accounts not in employee roster (security risk)
#   - Emits Prometheus metrics + Wazuh JSON events
#
# Rule IDs: 100800–100809
# Log: /var/log/employee-gworkspace-wazuh.log
set -euo pipefail

echo "=== Employee ↔ GWorkspace Reconciliation Deploy ==="

# ── Step 0: Patch SA_KEY path in all collectors (root required) ─────────
echo "Step 0: SA_KEY path → /keys/"
OLD_KEY="/opt/monitoring/gam-project-gf5mq-97886701cbdd.json"
NEW_KEY="/keys/gam-project-gf5mq-97886701cbdd.json"
for f in \
    /opt/monitoring/bin/gworkspace-collector.py \
    /etc/systemd/system/gworkspace-collector.service \
    /etc/systemd/system/employee-reconcile.service; do
  [ -f "$f" ] && sed -i "s|$OLD_KEY|$NEW_KEY|g" "$f" && echo "  Patched $f"
done
systemctl daemon-reload

# Verify key is accessible
if [ ! -f "$NEW_KEY" ]; then
  echo "  WARN: $NEW_KEY not found — place SA key there before running collector"
else
  echo "  SA key found: $NEW_KEY"
fi
echo ""
echo ""

# ── Step 1: Employee roster seed file ──────────────────────────────────
echo "Step 1: Employee roster"
if [ ! -f /opt/monitoring/data/employees.json ]; then
  cat > /opt/monitoring/data/employees.json << 'EMPLOYEES'
[
  {
    "email": "brian.monte@yokly.gives",
    "name": "Brian Monte",
    "department": "IT",
    "status": "active"
  },
  {
    "email": "dan@agapay.gives",
    "name": "Dan",
    "department": "Leadership",
    "status": "active"
  },
  {
    "email": "it_dept@yokly.gives",
    "name": "IT Department (shared)",
    "department": "IT",
    "status": "active"
  },
  {
    "email": "calvin@yokly.gives",
    "name": "Calvin",
    "department": "Leadership",
    "status": "active"
  },
  {
    "email": "tim@agapay.gives",
    "name": "Tim",
    "department": "Leadership",
    "status": "active"
  },
  {
    "email": "eddie@agapay.gives",
    "name": "Eddie",
    "department": "Leadership",
    "status": "active"
  },
  {
    "email": "kalekennen.ragudoo@yokly.gives",
    "name": "Kalekennen Ragudoo",
    "department": "Unknown",
    "status": "active"
  },
  {
    "email": "alaine.labrador@yokly.gives",
    "name": "Alaine Labrador",
    "department": "Unknown",
    "status": "active"
  },
  {
    "email": "andrea@yokly.gives",
    "name": "Andrea",
    "department": "Unknown",
    "status": "active"
  },
  {
    "email": "genessa@agapay.gives",
    "name": "Genessa",
    "department": "Unknown",
    "status": "active"
  },
  {
    "email": "lee@yokly.gives",
    "name": "Lee",
    "department": "Unknown",
    "status": "active"
  }
]
EMPLOYEES
  echo "  Created initial employees.json with known users"
  echo "  *** ACTION REQUIRED: populate /opt/monitoring/data/employees.json with all staff ***"
else
  COUNT=$(python3 -c "import json; d=json.load(open('/opt/monitoring/data/employees.json')); print(len(d))")
  echo "  employees.json exists: $COUNT employees"
fi

# ── Step 2: Reconciliation collector script ─────────────────────────────
echo ""
echo "Step 2: Collector script"
cat > /opt/monitoring/bin/employee-gworkspace-reconcile.py << 'PYEOF'
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

SA_KEY   = os.environ.get("SA_KEY",    "/keys/gam-project-gf5mq-97886701cbdd.json")
ADMIN    = os.environ.get("ADMIN_EMAIL","brian.monte@yokly.gives")
ROSTER   = Path(os.environ.get("ROSTER_FILE", "/opt/monitoring/data/employees.json"))
PROMFILE = Path(os.environ.get("PROMFILE", "/opt/monitoring/textfile_collector/employee_reconcile.prom"))
LOGFILE  = Path(os.environ.get("LOGFILE",  "/var/log/employee-gworkspace-wazuh.log"))

ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

prom = []
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
    event = {
        "timestamp": ts,
        "source": "employee_reconcile",
        "alertname": alertname,
        "severity": severity,
        "summary": summary,
    }
    event.update(extra)
    wazuh.append(json.dumps(event))

def fail(msg):
    emit_prom("employee_reconcile_collector_up", 0,
              help_text="1 if collector ran successfully")
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

# Build lookup by email (lower-cased)
roster_emails  = {e["email"].lower() for e in employees if e.get("status") == "active"}
roster_all     = {e["email"].lower(): e for e in employees}

# ── Fetch live GWorkspace users ─────────────────────────────────────────
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
except ImportError:
    fail("google-api-python-client not installed")

SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]
try:
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY, scopes=SCOPES, subject=ADMIN
    )
except Exception as e:
    fail(f"Auth failed: {e}")

try:
    svc = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
    gw_users = []
    request = svc.users().list(customer="my_customer", maxResults=500,
                                orderBy="email", fields="nextPageToken,users(primaryEmail,suspended,isAdmin,name)")
    while request:
        resp = request.execute()
        gw_users.extend(resp.get("users", []))
        request = svc.users().list_next(request, resp)
except Exception as e:
    fail(f"GWorkspace API error: {e}")

# ── Reconcile ──────────────────────────────────────────────────────────
gw_active   = {u["primaryEmail"].lower(): u for u in gw_users if not u.get("suspended", False)}
gw_suspended= {u["primaryEmail"].lower(): u for u in gw_users if u.get("suspended", False)}
gw_admin    = {u["primaryEmail"].lower(): u for u in gw_users if u.get("isAdmin", False)}
gw_all      = {u["primaryEmail"].lower(): u for u in gw_users}

# 1. Orphaned GW accounts — active GW users NOT in employee roster
orphaned = []
for email, u in gw_active.items():
    if email not in roster_all:
        orphaned.append({
            "email": email,
            "name": u.get("name", {}).get("fullName", ""),
            "is_admin": u.get("isAdmin", False),
        })

# 2. Missing GW accounts — active employees with NO GW account
missing_gw = []
for email in roster_emails:
    if email not in gw_all:
        emp = roster_all[email]
        missing_gw.append({
            "email": email,
            "name": emp.get("name", ""),
            "department": emp.get("department", ""),
        })

# 3. Suspended GW but listed as active employee
suspended_active = []
for email in roster_emails:
    if email in gw_suspended:
        emp = roster_all[email]
        suspended_active.append({
            "email": email,
            "name": emp.get("name", ""),
            "department": emp.get("department", ""),
        })

# 4. Admin accounts not in employee roster
admin_unregistered = []
for email, u in gw_admin.items():
    if email not in roster_all:
        admin_unregistered.append({
            "email": email,
            "name": u.get("name", {}).get("fullName", ""),
        })

# ── Emit Prometheus metrics ────────────────────────────────────────────
emit_prom("employee_reconcile_collector_up", 1,
          help_text="1 if collector ran successfully")
emit_prom("employee_reconcile_employees_total", len(employees),
          help_text="Total employees in roster")
emit_prom("employee_reconcile_active_employees", len(roster_emails),
          help_text="Active employees in roster")
emit_prom("employee_reconcile_gw_users_total", len(gw_users),
          help_text="Total Google Workspace users")
emit_prom("employee_reconcile_gw_active_total", len(gw_active),
          help_text="Active (non-suspended) GW users")
emit_prom("employee_reconcile_orphaned_accounts", len(orphaned),
          help_text="GW accounts with no employee record")
emit_prom("employee_reconcile_missing_gw_accounts", len(missing_gw),
          help_text="Active employees with no GW account")
emit_prom("employee_reconcile_suspended_active_employees", len(suspended_active),
          help_text="Active employees whose GW account is suspended")
emit_prom("employee_reconcile_admin_unregistered", len(admin_unregistered),
          help_text="GW admin accounts not in employee roster")
emit_prom("employee_reconcile_last_run_timestamp", int(datetime.datetime.now().timestamp()),
          help_text="Unix timestamp of last successful run")

# Per-orphan metrics with email label
prom.append("# HELP employee_reconcile_orphan_info 1 for each orphaned GW account")
prom.append("# TYPE employee_reconcile_orphan_info gauge")
for o in orphaned:
    is_admin_str = "true" if o["is_admin"] else "false"
    lbl = f'email="{o["email"]}",name="{o["name"]}",is_admin="{is_admin_str}"'
    prom.append(f"employee_reconcile_orphan_info{{{lbl}}} 1")

# Per-missing metrics
prom.append("# HELP employee_reconcile_missing_info 1 for each employee missing a GW account")
prom.append("# TYPE employee_reconcile_missing_info gauge")
for m in missing_gw:
    lbl = f'email="{m["email"]}",name="{m["name"]}",department="{m["department"]}"'
    prom.append(f"employee_reconcile_missing_info{{{lbl}}} 1")

# ── Emit Wazuh events ──────────────────────────────────────────────────
# Summary event (every run)
emit_wazuh("EmployeeReconcileSummary", "info",
    f"Reconcile: {len(roster_emails)} employees, {len(gw_active)} GW active, "
    f"{len(orphaned)} orphaned, {len(missing_gw)} missing, "
    f"{len(suspended_active)} suspended-active, {len(admin_unregistered)} admin-unregistered",
    employees_active=len(roster_emails),
    gw_users_active=len(gw_active),
    orphaned_count=len(orphaned),
    missing_count=len(missing_gw),
    suspended_active_count=len(suspended_active),
    admin_unregistered_count=len(admin_unregistered),
)

# Orphaned accounts (most important — offboarding risk)
for o in orphaned:
    sev = "critical" if o["is_admin"] else "warning"
    emit_wazuh("EmployeeOrphanedGWAccount", sev,
        f"GW account {o['email']} has no employee record — possible orphaned account",
        email=o["email"],
        full_name=o["name"],
        is_admin=str(o["is_admin"]).lower(),
    )

# Admin accounts not in roster
for a in admin_unregistered:
    emit_wazuh("EmployeeAdminUnregistered", "critical",
        f"GW admin account {a['email']} is NOT in employee roster — unauthorized admin",
        email=a["email"],
        full_name=a["name"],
    )

# Active employees with suspended GW
for s in suspended_active:
    emit_wazuh("EmployeeSuspendedActive", "warning",
        f"Employee {s['email']} is active in roster but GW account is suspended",
        email=s["email"],
        name=s["name"],
        department=s["department"],
    )

# Employees missing GW account
for m in missing_gw:
    emit_wazuh("EmployeeMissingGWAccount", "info",
        f"Employee {m['email']} in roster has no Google Workspace account",
        email=m["email"],
        name=m["name"],
        department=m["department"],
    )

# ── Write output ────────────────────────────────────────────────────────
PROMFILE.write_text("\n".join(prom) + "\n")
with LOGFILE.open("a") as f:
    f.write("\n".join(wazuh) + "\n")

print(f"Reconcile OK: {len(roster_emails)} employees / {len(gw_active)} GW active / "
      f"{len(orphaned)} orphaned / {len(missing_gw)} missing GW / "
      f"{len(admin_unregistered)} admin-unregistered")
PYEOF
chmod +x /opt/monitoring/bin/employee-gworkspace-reconcile.py
echo "  Collector written"

# ── Step 3: Log file ────────────────────────────────────────────────────
echo ""
echo "Step 3: Log file"
touch /var/log/employee-gworkspace-wazuh.log
chmod 644 /var/log/employee-gworkspace-wazuh.log
echo "  /var/log/employee-gworkspace-wazuh.log created"

# ── Step 4: Wazuh logcollector config ──────────────────────────────────
echo ""
echo "Step 4: Wazuh logcollector"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if grep -q "employee-gworkspace-wazuh" "$OSSEC_CONF" 2>/dev/null; then
  echo "  logcollector entry already present"
else
  # Insert before closing </ossec_config>
  python3 << 'PYINSERT'
import re
path = "/var/ossec/etc/ossec.conf"
with open(path) as f:
    content = f.read()
stanza = """
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/employee-gworkspace-wazuh.log</location>
  </localfile>
"""
content = content.replace("</ossec_config>", stanza + "</ossec_config>")
with open(path, "w") as f:
    f.write(content)
print("  logcollector entry added")
PYINSERT
fi

# ── Step 5: Wazuh decoder ───────────────────────────────────────────────
echo ""
echo "Step 5: Wazuh decoder"
cat > /var/ossec/etc/decoders/employee_reconcile_decoder.xml << 'DECODER'
<decoder name="employee_reconcile">
  <prematch>{"source":"employee_reconcile"</prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
DECODER
chown wazuh:wazuh /var/ossec/etc/decoders/employee_reconcile_decoder.xml
echo "  Decoder written"

# ── Step 6: Wazuh rules ────────────────────────────────────────────────
echo ""
echo "Step 6: Wazuh rules (100800–100809)"
cat > /var/ossec/etc/rules/employee_reconcile_rules.xml << 'RULES'
<group name="employee_reconcile,google_workspace,">

  <!-- 100800: Base match for all employee reconcile events -->
  <rule id="100800" level="2">
    <decoded_as>json</decoded_as>
    <field name="source">employee_reconcile</field>
    <description>Employee ↔ GWorkspace reconciliation event</description>
    <group>employee_reconcile,</group>
  </rule>

  <!-- 100801: Summary (every run — informational) -->
  <rule id="100801" level="2">
    <if_sid>100800</if_sid>
    <field name="alertname">EmployeeReconcileSummary</field>
    <description>Employee reconcile: $(summary)</description>
    <group>employee_reconcile,info,</group>
  </rule>

  <!-- 100802: Orphaned GW account (not admin) -->
  <rule id="100802" level="8">
    <if_sid>100800</if_sid>
    <field name="alertname">EmployeeOrphanedGWAccount</field>
    <field name="is_admin">false</field>
    <description>Orphaned GW account: $(email) has no employee record</description>
    <group>employee_reconcile,offboarding,identity,</group>
  </rule>

  <!-- 100803: Orphaned GW account that is also an ADMIN — critical -->
  <rule id="100803" level="12">
    <if_sid>100800</if_sid>
    <field name="alertname">EmployeeOrphanedGWAccount</field>
    <field name="is_admin">true</field>
    <description>CRITICAL: Orphaned GW ADMIN account: $(email) — unauthorized admin access</description>
    <group>employee_reconcile,offboarding,identity,privilege_escalation,</group>
  </rule>

  <!-- 100804: Admin account not in employee roster -->
  <rule id="100804" level="12">
    <if_sid>100800</if_sid>
    <field name="alertname">EmployeeAdminUnregistered</field>
    <description>CRITICAL: GW admin $(email) not in employee roster — unauthorized admin</description>
    <group>employee_reconcile,identity,privilege_escalation,</group>
  </rule>

  <!-- 100805: Active employee with suspended GW account -->
  <rule id="100805" level="5">
    <if_sid>100800</if_sid>
    <field name="alertname">EmployeeSuspendedActive</field>
    <description>Active employee $(email) has suspended GW account</description>
    <group>employee_reconcile,identity,</group>
  </rule>

  <!-- 100806: Employee missing GW account (provisioning gap) -->
  <rule id="100806" level="4">
    <if_sid>100800</if_sid>
    <field name="alertname">EmployeeMissingGWAccount</field>
    <description>Employee $(email) has no Google Workspace account</description>
    <group>employee_reconcile,identity,provisioning,</group>
  </rule>

  <!-- 100807: Collector failed -->
  <rule id="100807" level="10">
    <if_sid>100800</if_sid>
    <field name="alertname">EmployeeReconcileCollectorDown</field>
    <description>Employee reconcile collector failed: $(summary)</description>
    <group>employee_reconcile,collector_down,</group>
  </rule>

</group>
RULES
echo "  Rules written (100800–100807)"

# ── Step 7: Prometheus alert rules ─────────────────────────────────────
echo ""
echo "Step 7: Prometheus alert rules"
# Append to gworkspace.rules.yml if not already present
if grep -q "EmployeeReconcile" /opt/monitoring/rules/gworkspace.rules.yml 2>/dev/null; then
  echo "  Alert rules already present"
else
  cat >> /opt/monitoring/rules/gworkspace.rules.yml << 'PROMRULES'

  # --- Employee ↔ GWorkspace Reconciliation ---

  - alert: EmployeeOrphanedGWAccount
    expr: employee_reconcile_orphaned_accounts > 0
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "{{ $value }} GW account(s) have no employee record — possible orphaned accounts"
      description: "Check employee_reconcile_orphan_info metric for affected emails. May indicate offboarded employees still with access."

  - alert: EmployeeAdminUnregistered
    expr: employee_reconcile_admin_unregistered > 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "{{ $value }} GW admin account(s) NOT in employee roster — unauthorized admin"

  - alert: EmployeeSuspendedActive
    expr: employee_reconcile_suspended_active_employees > 0
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "{{ $value }} employee(s) active in roster but GW account is suspended"

  - alert: EmployeeReconcileDown
    expr: employee_reconcile_collector_up == 0
    for: 15m
    labels:
      severity: critical
    annotations:
      summary: "Employee reconcile collector is failing"

  - alert: EmployeeGWCountMismatch
    expr: abs(employee_reconcile_active_employees - employee_reconcile_gw_active_total) > 5
    for: 30m
    labels:
      severity: warning
    annotations:
      summary: "Employee count ({{ employee_reconcile_active_employees }}) vs GW active users ({{ employee_reconcile_gw_active_total }}) differ by more than 5"
PROMRULES
  echo "  Alert rules appended to gworkspace.rules.yml"
fi

# ── Step 8: Systemd timer ───────────────────────────────────────────────
echo ""
echo "Step 8: Systemd timer (every 30 min)"
cat > /etc/systemd/system/employee-reconcile.service << 'SVC'
[Unit]
Description=Employee ↔ GWorkspace Reconciliation Collector
After=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=-/opt/monitoring/.env
ExecStart=/opt/monitoring/bin/employee-gworkspace-reconcile.py
StandardOutput=journal
StandardError=journal
SVC

cat > /etc/systemd/system/employee-reconcile.timer << 'TMR'
[Unit]
Description=Run employee↔GWorkspace reconciliation every 30 minutes
Requires=employee-reconcile.service

[Timer]
OnBootSec=2min
OnUnitActiveSec=30min
Persistent=true

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now employee-reconcile.timer
echo "  Timer enabled (employee-reconcile.timer)"

# ── Step 9: Reload Wazuh + Prometheus ──────────────────────────────────
echo ""
echo "Step 9: Reload services"
systemctl restart wazuh-manager 2>/dev/null && echo "  Wazuh restarted" || echo "  WARN: wazuh restart failed"
sleep 2
curl -sf -X POST http://127.0.0.1:9090/-/reload && echo "  Prometheus reloaded" || echo "  WARN: Prometheus reload failed"

# ── Step 10: First run ──────────────────────────────────────────────────
echo ""
echo "Step 10: First reconciliation run"
SA_KEY=/keys/gam-project-gf5mq-97886701cbdd.json \
ADMIN_EMAIL=brian.monte@yokly.gives \
  /opt/monitoring/bin/employee-gworkspace-reconcile.py && echo "  First run OK" || echo "  WARN: first run failed (check credentials)"

# ── Done ────────────────────────────────────────────────────────────────
echo ""
echo "=== Deploy complete ==="
echo ""
echo "Rule ID summary:"
echo "  100800  Base decoder match"
echo "  100801  Reconcile summary (every 30 min, level 2)"
echo "  100802  Orphaned GW account — no employee record (level 8)"
echo "  100803  Orphaned GW account + admin (level 12 — CRITICAL)"
echo "  100804  Admin account not in roster (level 12 — CRITICAL)"
echo "  100805  Active employee with suspended GW (level 5)"
echo "  100806  Employee with no GW account — provisioning gap (level 4)"
echo "  100807  Collector down (level 10)"
echo ""
echo "Prometheus alerts:"
echo "  EmployeeOrphanedGWAccount   (warning)  — any orphaned accounts"
echo "  EmployeeAdminUnregistered   (critical) — admin not in roster"
echo "  EmployeeSuspendedActive     (warning)  — employee account suspended"
echo "  EmployeeReconcileDown       (critical) — collector failing"
echo "  EmployeeGWCountMismatch     (warning)  — headcount drift > 5"
echo ""
echo "Next: populate /opt/monitoring/data/employees.json with all 99 staff"
echo "      Run: systemctl start employee-reconcile.service"
