#!/usr/bin/env python3
"""
Reads the Employee sheet from Google Sheets.
Filters rows where Status == "Active".
Writes /opt/monitoring/data/employees.json.
Then runs the reconciliation collector.
"""
import json, os, sys
from pathlib import Path

SA_KEY     = os.environ.get("SA_KEY", "/keys/gam-project-gf5mq-97886701cbdd.json")
ADMIN      = os.environ.get("ADMIN_EMAIL", "brian.monte@yokly.gives")
SHEET_ID   = "1gmXUiOgwqEc1yMtX9DmNJbckzJE9IWiHpVtJU02y58o"
SHEET_NAME = "Employees"
OUT        = Path(os.environ.get("OUT_FILE", "/opt/monitoring/data/employees.json"))

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
except ImportError:
    print("ERROR: google-api-python-client not installed", file=sys.stderr)
    sys.exit(1)

SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"]
creds = service_account.Credentials.from_service_account_file(SA_KEY, scopes=SCOPES)
svc   = build("sheets", "v4", credentials=creds, cache_discovery=False)

print(f"Reading sheet: {SHEET_ID} → '{SHEET_NAME}'")
result = svc.spreadsheets().values().get(
    spreadsheetId=SHEET_ID,
    range=f"{SHEET_NAME}!A1:AZ"
).execute()

rows = result.get("values", [])
if not rows:
    print("ERROR: Sheet is empty", file=sys.stderr)
    sys.exit(1)

# First row = headers (normalize to lowercase, strip spaces)
headers = [h.strip().lower() for h in rows[0]]
print(f"Headers: {headers}")

# Locate required columns
def col(name):
    for variant in [name, name.lower(), name.upper(), name.title()]:
        if variant.lower() in headers:
            return headers.index(variant.lower())
    return None

idx_status = col("status")
idx_email  = col("email") or col("email address") or col("work email")
idx_name   = col("name") or col("full name") or col("employee name")
idx_dept   = col("department") or col("dept") or col("team")

if idx_status is None:
    print(f"ERROR: 'Status' column not found. Headers: {headers}", file=sys.stderr)
    sys.exit(1)
if idx_email is None:
    print(f"ERROR: 'Email' column not found. Headers: {headers}", file=sys.stderr)
    sys.exit(1)

print(f"  Status col: {idx_status}, Email col: {idx_email}, "
      f"Name col: {idx_name}, Dept col: {idx_dept}")

def cell(row, idx):
    if idx is None or idx >= len(row):
        return ""
    return row[idx].strip()

employees = []
skipped   = 0

for i, row in enumerate(rows[1:], start=2):
    status = cell(row, idx_status)
    if status.lower() != "active":
        skipped += 1
        continue

    email = cell(row, idx_email).lower()
    if not email or "@" not in email:
        print(f"  Row {i}: skipping — no valid email (status=Active)")
        continue

    emp = {
        "email":      email,
        "name":       cell(row, idx_name)  if idx_name  is not None else "",
        "department": cell(row, idx_dept)  if idx_dept  is not None else "",
        "status":     "active",
    }
    employees.append(emp)

print(f"\nResult: {len(employees)} active employees, {skipped} skipped (non-active)")

# Write output
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(employees, indent=2))
print(f"Written: {OUT}")

# Print summary
from collections import Counter
depts = Counter(e["department"] for e in employees if e["department"])
print("\nBy department:")
for dept, count in sorted(depts.items(), key=lambda x: -x[1]):
    print(f"  {dept}: {count}")
