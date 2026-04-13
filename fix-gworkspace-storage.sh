#!/usr/bin/env bash
set -euo pipefail

echo "=== Fixing storage metric to use total_quota_in_mb (active storage, no trash) ==="

# Replace used_quota_in_mb with total_quota_in_mb in collector
sed -i 's/parameters="accounts:used_quota_in_mb"/parameters="accounts:used_quota_in_mb,accounts:drive_used_quota_in_mb,accounts:gmail_used_quota_in_mb,accounts:gplus_photos_used_quota_in_mb"/' /opt/monitoring/bin/gworkspace-collector.py

# Actually, let's replace the whole storage section properly
python3 << 'PYFIX'
import re
path = "/opt/monitoring/bin/gworkspace-collector.py"
with open(path) as f:
    code = f.read()

# Replace the storage parameter query and field extraction
old = '''                req = reports_svc.userUsageReport().get(
                    userKey=email, date=d,
                    parameters="accounts:used_quota_in_mb",
                )
                resp = exec_with_retries(req)
                for entry in resp.get("usageReports", []) or []:
                    for p in entry.get("parameters", []) or []:
                        if p.get("name") == "accounts:used_quota_in_mb":
                            mb = int(p.get("intValue", 0))
                            usage = mb * 1024 * 1024'''

new = '''                req = reports_svc.userUsageReport().get(
                    userKey=email, date=d,
                    parameters="accounts:used_quota_in_mb,accounts:drive_used_quota_in_mb,accounts:gmail_used_quota_in_mb,accounts:gplus_photos_used_quota_in_mb",
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
                # Use sum of individual services (matches admin console)
                usage = (drive_mb + gmail_mb + photos_mb) * 1024 * 1024
                drive_bytes = drive_mb * 1024 * 1024
                gmail_bytes = gmail_mb * 1024 * 1024
                photos_bytes = photos_mb * 1024 * 1024'''

code = code.replace(old, new)

# Add per-service metrics emission after the usage > 10GB check
old2 = '''        if usage > 10 * 1024**3:  # only track users > 10GB
            emit_prom("gworkspace_drive_usage_bytes", usage,
                      {"user": email, "exempt": str(is_exempt).lower()})'''

new2 = '''        if usage > 10 * 1024**3:  # only track users > 10GB
            emit_prom("gworkspace_drive_usage_bytes", usage,
                      {"user": email, "exempt": str(is_exempt).lower()})
            emit_prom("gworkspace_drive_only_bytes", drive_bytes,
                      {"user": email})
            emit_prom("gworkspace_gmail_usage_bytes", gmail_bytes,
                      {"user": email})
            emit_prom("gworkspace_photos_usage_bytes", photos_bytes,
                      {"user": email})'''

code = code.replace(old2, new2)

with open(path, "w") as f:
    f.write(code)
print("  Collector updated")
PYFIX

echo ""
echo "=== Adding org-wide storage metrics ==="
# Add customer usage report section before the Write outputs section
python3 << 'PYFIX2'
path = "/opt/monitoring/bin/gworkspace-collector.py"
with open(path) as f:
    code = f.read()

org_section = '''
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
                parameters="accounts:used_quota_in_mb,accounts:total_quota_in_mb"
            ).execute()
            org_used = 0
            org_total = 0
            for entry in resp.get("usageReports", []) or []:
                for p in entry.get("parameters", []) or []:
                    name = p.get("name", "")
                    val = int(p.get("intValue", 0))
                    if name == "accounts:used_quota_in_mb":
                        org_used = val * 1024 * 1024
                    elif name == "accounts:total_quota_in_mb":
                        org_total = val * 1024 * 1024

            prom_lines.append("# HELP gworkspace_org_storage_used_bytes Org total storage used")
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

            print(f"  Org storage: {org_used / 1024**4:.2f} TB used of {org_total / 1024**4:.2f} TB ({(org_used/org_total*100) if org_total else 0:.1f}%)")
            break
        except Exception:
            continue

except Exception as e:
    print(f"WARNING: Customer usage: {e}", file=sys.stderr)
    errors += 1
'''

# Insert before "# Write outputs"
code = code.replace("# ============================================================\n# Write outputs", org_section + "# ============================================================\n# Write outputs")

with open(path, "w") as f:
    f.write(code)
print("  Added org-wide storage metrics")
PYFIX2

echo ""
echo "=== Test run ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "=== Check Kale's storage ==="
grep "kalekennen" /opt/monitoring/textfile_collector/gworkspace.prom

echo ""
echo "=== Check org storage ==="
grep "org_storage" /opt/monitoring/textfile_collector/gworkspace.prom | grep -v "^#"
