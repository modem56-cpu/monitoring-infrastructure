#!/usr/bin/env bash
set -euo pipefail

echo "=== Adding shared drive metrics to collector ==="

python3 << 'PYFIX'
path = "/opt/monitoring/bin/gworkspace-collector.py"
with open(path) as f:
    code = f.read()

# Add shared drive collection after the org storage section, before "Write outputs"
shared_drive_section = '''
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

'''

# Insert before "# Write outputs" (which should be preceded by the section comment)
marker = "# ============================================================\n# Write outputs"
if marker in code:
    code = code.replace(marker, shared_drive_section + marker)
    with open(path, "w") as f:
        f.write(code)
    print("  Added shared drive metrics collection")
else:
    print("  ERROR: Could not find insertion point")
PYFIX

# Add drive.readonly scope to the SCOPES list
sed -i 's|"https://www.googleapis.com/auth/apps.alerts",|"https://www.googleapis.com/auth/apps.alerts",\n    "https://www.googleapis.com/auth/drive.readonly",|' /opt/monitoring/bin/gworkspace-collector.py

echo ""
echo "=== Test run ==="
python3 /opt/monitoring/bin/gworkspace-collector.py 2>&1

echo ""
echo "=== Shared drive metrics ==="
grep "shared_drive" /opt/monitoring/textfile_collector/gworkspace.prom | grep -v "^#" | sort -t' ' -k2 -rn | head -10
