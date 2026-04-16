#!/usr/bin/env python3
"""
List all users in a given OU path (and sub-OUs).
Usage:
    python3 list-ou-users.py "/Yokly/Marketing"
    python3 list-ou-users.py "/Yokly/Marketing" --csv
"""
import json, sys, os

SA_KEY    = os.environ.get("SA_KEY", "/opt/monitoring/gam-project-gf5mq-97886701cbdd.json")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "brian.monte@yokly.gives")

SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
]

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("ERROR: google-api-python-client not installed", file=sys.stderr)
    sys.exit(1)

# ── args ──────────────────────────────────────────────────────
if len(sys.argv) < 2:
    print("Usage: python3 list-ou-users.py \"<OU path>\" [--csv]")
    print('Example: python3 list-ou-users.py "/Yokly/Marketing"')
    sys.exit(1)

ou_path  = sys.argv[1]
csv_mode = "--csv" in sys.argv

# ── auth ──────────────────────────────────────────────────────
try:
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY, scopes=SCOPES, subject=ADMIN_EMAIL
    )
except Exception as e:
    print(f"ERROR: Auth failed: {e}", file=sys.stderr)
    sys.exit(1)

dir_svc = build("admin", "directory_v1", credentials=creds, cache_discovery=False)

# ── fetch users in OU (recursive) ────────────────────────────
users = []
page_token = None

print(f"Fetching users in OU: {ou_path}", file=sys.stderr)

while True:
    try:
        resp = dir_svc.users().list(
            customer="my_customer",
            query=f"orgUnitPath='{ou_path}'",
            orderBy="email",
            projection="basic",
            pageToken=page_token,
            maxResults=500,
        ).execute()
    except HttpError as e:
        print(f"ERROR: Directory API: {e}", file=sys.stderr)
        sys.exit(1)

    batch = resp.get("users", [])
    users.extend(batch)
    page_token = resp.get("nextPageToken")
    if not page_token:
        break

print(f"Found {len(users)} user(s)\n", file=sys.stderr)

# ── output ────────────────────────────────────────────────────
if csv_mode:
    print("email,full_name,ou_path,suspended,last_login")
    for u in users:
        email     = u.get("primaryEmail", "")
        name      = u.get("name", {}).get("fullName", "")
        ou        = u.get("orgUnitPath", "")
        suspended = u.get("suspended", False)
        last_login = u.get("lastLoginTime", "never")
        print(f"{email},{name},{ou},{suspended},{last_login}")
else:
    for u in users:
        email     = u.get("primaryEmail", "")
        name      = u.get("name", {}).get("fullName", "")
        ou        = u.get("orgUnitPath", "")
        suspended = " [SUSPENDED]" if u.get("suspended") else ""
        last_login = u.get("lastLoginTime", "never")
        print(f"  {email:<40} {name:<30} {ou}{suspended}")
        print(f"    last login: {last_login}")
