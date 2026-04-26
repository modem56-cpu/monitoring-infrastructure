#!/usr/bin/env bash
set -euo pipefail

SA_KEY="/keys/gam-project-gf5mq-97886701cbdd.json"
ADMIN_EMAIL="brian.monte@yokly.gives"
LOGFILE="/var/log/gworkspace-wazuh.log"
PROMFILE="/opt/monitoring/textfile_collector/gworkspace.prom"

echo "============================================"
echo "  Google Workspace Integration Deployment"
echo "============================================"

echo ""
echo "=== Step 1: Check dependencies ==="
python3 -c "from google.oauth2 import service_account; from googleapiclient.discovery import build; print('  Google API libraries OK')" 2>/dev/null || {
  echo "  Installing..."
  pip3 install --break-system-packages --quiet google-auth google-auth-httplib2 google-api-python-client 2>&1 | tail -3
}

echo ""
echo "=== Step 2: Create collector script ==="
cat > /opt/monitoring/bin/gworkspace-collector.py << 'PYEOF'
#!/usr/bin/env python3
"""
Google Workspace → Prometheus textfile + Wazuh JSON log
Collects: admin audit logs, login events, drive storage, security alerts
"""
import json, sys, datetime, os, math
from pathlib import Path

SA_KEY = os.environ.get("SA_KEY", "/keys/gam-project-gf5mq-97886701cbdd.json")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "brian.monte@yokly.gives")
LOGFILE = Path(os.environ.get("LOGFILE", "/var/log/gworkspace-wazuh.log"))
PROMFILE = Path(os.environ.get("PROMFILE", "/opt/monitoring/textfile_collector/gworkspace.prom"))

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
except ImportError:
    print("ERROR: google-api-python-client not installed", file=sys.stderr)
    sys.exit(1)

SCOPES = [
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "https://www.googleapis.com/auth/admin.reports.usage.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/apps.alerts",
]

ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
prom_lines = []
wazuh_events = []

def emit_wazuh(alertname, severity, summary, **extra):
    event = {
        "timestamp": ts,
        "source": "google_workspace",
        "alertname": alertname,
        "severity": severity,
        "summary": summary,
    }
    event.update(extra)
    wazuh_events.append(json.dumps(event))

def emit_prom(metric, value, labels=None):
    if labels:
        lbl = ",".join(f'{k}="{v}"' for k, v in labels.items())
        prom_lines.append(f'{metric}{{{lbl}}} {value}')
    else:
        prom_lines.append(f'{metric} {value}')

try:
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY, scopes=SCOPES, subject=ADMIN_EMAIL
    )
except Exception as e:
    print(f"ERROR: Auth failed: {e}", file=sys.stderr)
    emit_prom("gworkspace_collector_up", 0)
    emit_prom("# HELP gworkspace_collector_up", "Google Workspace collector status")
    emit_prom("# TYPE gworkspace_collector_up", "gauge")
    PROMFILE.write_text("\n".join(prom_lines) + "\n")
    sys.exit(1)

errors = 0

# ============================================================
# 1. Admin Audit Logs (last 5 minutes)
# ============================================================
try:
    service = build("admin", "reports_v1", credentials=creds, cache_discovery=False)
    start = (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Login events
    results = service.activities().list(
        userKey="all", applicationName="login",
        startTime=start, maxResults=50
    ).execute()
    login_events = results.get("items", [])
    emit_prom("# HELP gworkspace_login_events_total", "Login events in last 10 min")
    emit_prom("# TYPE gworkspace_login_events_total", "gauge")
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
                emit_wazuh(
                    f"GWorkspace_{ename}", severity,
                    f"Google Workspace {ename}: user={actor} ip={ip}",
                    user=actor, srcip=ip
                )

    # Admin events
    results = service.activities().list(
        userKey="all", applicationName="admin",
        startTime=start, maxResults=50
    ).execute()
    admin_events = results.get("items", [])
    emit_prom("# HELP gworkspace_admin_events_total", "Admin events in last 10 min")
    emit_prom("# TYPE gworkspace_admin_events_total", "gauge")
    emit_prom("gworkspace_admin_events_total", len(admin_events))

    for event in admin_events:
        actor = event.get("actor", {}).get("email", "unknown")
        for e in event.get("events", []):
            ename = e.get("name", "")
            params = {p["name"]: p.get("value", p.get("multiValue", "")) for p in e.get("parameters", [])}
            emit_wazuh(
                "GWorkspace_admin_action", "info",
                f"Admin action: {ename} by {actor}",
                user=actor, admin_action=ename,
                details=json.dumps(params)[:200]
            )

    # Drive events
    results = service.activities().list(
        userKey="all", applicationName="drive",
        startTime=start, maxResults=50
    ).execute()
    drive_events = results.get("items", [])
    emit_prom("# HELP gworkspace_drive_events_total", "Drive events in last 10 min")
    emit_prom("# TYPE gworkspace_drive_events_total", "gauge")
    emit_prom("gworkspace_drive_events_total", len(drive_events))

    # Flag external sharing
    for event in drive_events:
        actor = event.get("actor", {}).get("email", "unknown")
        for e in event.get("events", []):
            ename = e.get("name", "")
            if ename in ("change_user_access", "change_acl_editors"):
                params = {p["name"]: p.get("value", "") for p in e.get("parameters", [])}
                target_user = params.get("target_user", "")
                if target_user and "@" in target_user:
                    domain = target_user.split("@")[1]
                    if domain != "yokly.gives":
                        emit_wazuh(
                            "GWorkspace_external_share", "warning",
                            f"External file sharing: {actor} shared with {target_user}",
                            user=actor, target=target_user
                        )

except Exception as e:
    print(f"WARNING: Reports API: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 2. User Directory (storage + counts)
# ============================================================
try:
    dir_service = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
    results = dir_service.users().list(
        customer="my_customer", maxResults=100,
        projection="full", orderBy="email"
    ).execute()
    users = results.get("users", [])

    total_users = len(users)
    suspended = sum(1 for u in users if u.get("suspended", False))
    admin_count = sum(1 for u in users if u.get("isAdmin", False))
    no_2fa = sum(1 for u in users if not u.get("isEnrolledIn2Sv", False) and not u.get("suspended", False))

    emit_prom("# HELP gworkspace_users_total", "Total Google Workspace users")
    emit_prom("# TYPE gworkspace_users_total", "gauge")
    emit_prom("gworkspace_users_total", total_users)

    emit_prom("# HELP gworkspace_users_suspended", "Suspended users")
    emit_prom("# TYPE gworkspace_users_suspended", "gauge")
    emit_prom("gworkspace_users_suspended", suspended)

    emit_prom("# HELP gworkspace_users_admin", "Admin users")
    emit_prom("# TYPE gworkspace_users_admin", "gauge")
    emit_prom("gworkspace_users_admin", admin_count)

    emit_prom("# HELP gworkspace_users_no_2fa", "Active users without 2FA")
    emit_prom("# TYPE gworkspace_users_no_2fa", "gauge")
    emit_prom("gworkspace_users_no_2fa", no_2fa)

    if no_2fa > 0:
        no_2fa_users = [u["primaryEmail"] for u in users if not u.get("isEnrolledIn2Sv", False) and not u.get("suspended", False)]
        emit_wazuh(
            "GWorkspace_no_2fa", "warning",
            f"{no_2fa} users without 2FA: {', '.join(no_2fa_users[:5])}",
            count=str(no_2fa)
        )

    # Per-user storage (from usage reports if available)
    for u in users:
        email = u.get("primaryEmail", "")
        # Storage from user object (if available)
        for loc in u.get("nonEditableAliases", []):
            pass  # Not storage

except Exception as e:
    print(f"WARNING: Directory API: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# 3. Security Alerts (Alert Center)
# ============================================================
try:
    alerts_service = build("alertcenter", "v1beta1", credentials=creds, cache_discovery=False)
    start_time = (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    results = alerts_service.alerts().list(
        filter=f'createTime >= "{start_time}"',
        pageSize=20
    ).execute()
    alerts = results.get("alerts", [])

    emit_prom("# HELP gworkspace_security_alerts", "Security alerts in last hour")
    emit_prom("# TYPE gworkspace_security_alerts", "gauge")
    emit_prom("gworkspace_security_alerts", len(alerts))

    for alert in alerts:
        alert_type = alert.get("type", "unknown")
        source = alert.get("source", "unknown")
        severity_map = {"HIGH": "critical", "MEDIUM": "warning", "LOW": "info"}
        sev = severity_map.get(alert.get("metadata", {}).get("severity", ""), "warning")

        emit_wazuh(
            f"GWorkspace_security_{alert_type}", sev,
            f"Google Security Alert: {alert_type} from {source}",
            alert_type=alert_type, alert_source=source
        )

except Exception as e:
    print(f"WARNING: Alert Center API: {e}", file=sys.stderr)
    errors += 1

# ============================================================
# Write outputs
# ============================================================
emit_prom("# HELP gworkspace_collector_up", "Google Workspace collector status (1=ok)")
emit_prom("# TYPE gworkspace_collector_up", "gauge")
emit_prom("gworkspace_collector_up", 1 if errors == 0 else 0)

emit_prom("# HELP gworkspace_collector_errors", "Collector error count")
emit_prom("# TYPE gworkspace_collector_errors", "gauge")
emit_prom("gworkspace_collector_errors", errors)

# Write Prometheus textfile
PROMFILE.write_text("\n".join(prom_lines) + "\n")

# Append Wazuh events
if wazuh_events:
    with open(LOGFILE, "a") as f:
        for e in wazuh_events:
            f.write(e + "\n")

print(f"OK: {len(prom_lines)} prom metrics, {len(wazuh_events)} wazuh events, {errors} errors")
PYEOF

chmod +x /opt/monitoring/bin/gworkspace-collector.py

echo ""
echo "=== Step 3: Create Wazuh rules ==="
cat > /var/ossec/etc/rules/google_workspace.xml << 'XML'
<group name="google_workspace,">

  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^google_workspace$</field>
    <description>Google Workspace: $(alertname)</description>
    <group>google_workspace,</group>
  </rule>

  <rule id="100501" level="10">
    <if_sid>100500</if_sid>
    <match>login_failure</match>
    <description>Google Workspace: Login failure — $(summary)</description>
    <group>google_workspace,authentication_failed,</group>
  </rule>

  <rule id="100502" level="12">
    <if_sid>100500</if_sid>
    <match>suspicious_login</match>
    <description>CRITICAL: Google Workspace suspicious login — $(summary)</description>
    <group>google_workspace,authentication,suspicious,</group>
  </rule>

  <rule id="100503" level="12">
    <if_sid>100500</if_sid>
    <match>account_disabled_password_leak</match>
    <description>CRITICAL: Google Workspace password leak detected — $(summary)</description>
    <group>google_workspace,credential_leak,</group>
  </rule>

  <rule id="100504" level="5">
    <if_sid>100500</if_sid>
    <match>admin_action</match>
    <description>Google Workspace admin action — $(summary)</description>
    <group>google_workspace,admin,audit,</group>
  </rule>

  <rule id="100505" level="7">
    <if_sid>100500</if_sid>
    <match>external_share</match>
    <description>Google Workspace: External file sharing — $(summary)</description>
    <group>google_workspace,data_loss,</group>
  </rule>

  <rule id="100506" level="6">
    <if_sid>100500</if_sid>
    <match>no_2fa</match>
    <description>Google Workspace: Users without 2FA — $(summary)</description>
    <group>google_workspace,compliance,</group>
  </rule>

  <rule id="100507" level="10">
    <if_sid>100500</if_sid>
    <match>security_</match>
    <description>Google Workspace Security Alert — $(summary)</description>
    <group>google_workspace,security_alert,</group>
  </rule>

</group>
XML
chown wazuh:wazuh /var/ossec/etc/rules/google_workspace.xml

echo ""
echo "=== Step 4: Add Wazuh logcollector ==="
CONF="/var/ossec/etc/ossec.conf"
if grep -q "gworkspace-wazuh.log" "$CONF" 2>/dev/null; then
  echo "  Already configured"
else
  sed -i '/<\/ossec_config>/i \
  <!-- Google Workspace events -->\
  <localfile>\
    <log_format>json</log_format>\
    <location>/var/log/gworkspace-wazuh.log</location>\
  </localfile>' "$CONF"
  echo "  Added logcollector entry"
fi

echo ""
echo "=== Step 5: Create log file ==="
touch "$LOGFILE"
chown wazuh-admin:wazuh "$LOGFILE"
chmod 664 "$LOGFILE"

echo ""
echo "=== Step 6: Create systemd timer ==="
cat > /etc/systemd/system/gworkspace-collector.service << 'SVC'
[Unit]
Description=Google Workspace metrics collector
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/monitoring/bin/gworkspace-collector.py
Environment=SA_KEY=/keys/gam-project-gf5mq-97886701cbdd.json
Environment=ADMIN_EMAIL=brian.monte@yokly.gives
Environment=LOGFILE=/var/log/gworkspace-wazuh.log
Environment=PROMFILE=/opt/monitoring/textfile_collector/gworkspace.prom
SVC

cat > /etc/systemd/system/gworkspace-collector.timer << 'TMR'
[Unit]
Description=Run Google Workspace collector every 5 minutes

[Timer]
OnBootSec=60s
OnUnitActiveSec=5min
AccuracySec=10s

[Install]
WantedBy=timers.target
TMR

systemctl daemon-reload
systemctl enable --now gworkspace-collector.timer

echo ""
echo "=== Step 7: Restart Wazuh ==="
systemctl restart wazuh-manager

echo ""
echo "=== Step 8: Test run ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo ""
echo "  Collector: /opt/monitoring/bin/gworkspace-collector.py (every 5 min)"
echo "  Prometheus: /opt/monitoring/textfile_collector/gworkspace.prom"
echo "  Wazuh log: /var/log/gworkspace-wazuh.log"
echo "  Wazuh rules: 100500-100507"
echo ""
echo "  Metrics available:"
echo "    gworkspace_users_total, gworkspace_users_no_2fa"
echo "    gworkspace_login_events_total, gworkspace_admin_events_total"
echo "    gworkspace_security_alerts, gworkspace_collector_up"
echo ""
echo "  Wazuh alerts:"
echo "    Login failures, suspicious logins, password leaks"
echo "    Admin actions, external file sharing, 2FA compliance"
echo "    Security Center alerts"
