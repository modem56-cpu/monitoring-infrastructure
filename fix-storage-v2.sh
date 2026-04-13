#!/usr/bin/env bash
set -euo pipefail

# Fix the storage extraction in the collector
python3 << 'PYFIX'
path = "/opt/monitoring/bin/gworkspace-collector.py"
with open(path) as f:
    code = f.read()

# Replace the broken extraction block (lines 230-246 area)
old = '''                req = reports_svc.userUsageReport().get(
                    userKey=email, date=d,
                    parameters="accounts:used_quota_in_mb,accounts:drive_used_quota_in_mb,accounts:gmail_used_quota_in_mb,accounts:gplus_photos_used_quota_in_mb",
                )
                resp = exec_with_retries(req)
                for entry in resp.get("usageReports", []) or []:
                    for p in entry.get("parameters", []) or []:
                        if p.get("name") == "accounts:used_quota_in_mb":
                            mb = int(p.get("intValue", 0))
                            usage = mb * 1024 * 1024
                break'''

new = '''                req = reports_svc.userUsageReport().get(
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
                break'''

if old in code:
    code = code.replace(old, new)
    print("  Fixed storage extraction")
else:
    print("  ERROR: Could not find old pattern to replace")
    print("  Searching for partial match...")
    if "accounts:used_quota_in_mb" in code:
        print("  Found old parameter reference")
    
with open(path, "w") as f:
    f.write(code)
PYFIX

echo ""
echo "=== Also initialize drive_bytes before the loop ==="
# Add default values before the if usage > 10GB check
sed -i '/        total_storage_bytes += usage/a\        drive_bytes = getattr(sys.modules[__name__], "drive_bytes", 0) if "drive_bytes" not in dir() else drive_bytes' /opt/monitoring/bin/gworkspace-collector.py 2>/dev/null || true

echo ""
echo "=== Test run ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "=== Kale storage ==="
grep "kalekennen" /opt/monitoring/textfile_collector/gworkspace.prom

echo ""
echo "=== Org storage ==="
grep "org_storage" /opt/monitoring/textfile_collector/gworkspace.prom | grep -v "^#"

echo ""
echo "=== Over quota ==="
grep "over_quota" /opt/monitoring/textfile_collector/gworkspace.prom | grep -v "^#"
