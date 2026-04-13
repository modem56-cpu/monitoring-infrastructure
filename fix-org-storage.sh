#!/usr/bin/env bash
set -euo pipefail

echo "=== Fixing org storage to use customer_used_quota_in_mb ==="

python3 << 'PYFIX'
path = "/opt/monitoring/bin/gworkspace-collector.py"
with open(path) as f:
    code = f.read()

old = '''    resp = cust_svc.customerUsageReports().get(
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

            print(f"  Org storage: {org_used / 1024**4:.2f} TB used of {org_total / 1024**4:.2f} TB ({(org_used/org_total*100) if org_total else 0:.1f}%)")'''

new = '''    resp = cust_svc.customerUsageReports().get(
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
            print(f"    Drive: {org_drive / 1024**4:.2f} TB | Gmail: {org_gmail / 1024**3:.1f} GB | Photos: {org_photos / 1024**3:.1f} GB | Shared Drives: {org_shared / 1024**4:.2f} TB")'''

if old in code:
    code = code.replace(old, new)
    with open(path, "w") as f:
        f.write(code)
    print("  Fixed org storage metrics")
else:
    print("  ERROR: Pattern not found")
PYFIX

echo ""
echo "=== Test run ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "=== Org storage ==="
grep "org_" /opt/monitoring/textfile_collector/gworkspace.prom | grep -v "^#"
