#!/usr/bin/env python3
"""
Google Drive External Sharing Audit
=====================================
Scans Shared Drives (and optionally My Drive per-user) for external sharing.
Classifies every external permission finding against an approved client
Shared Drive registry built from the client JSON exports.

Output reports (dry-run only — never modifies anything):
  reports/drive-audit/client_registry_normalized.csv
  reports/drive-audit/approved_client_shared_drives.csv
  reports/drive-audit/external_sharing_findings.csv
  reports/drive-audit/unmatched_shared_drives.csv

Usage:
  python3 gworkspace-drive-audit.py                         # Shared drives only (recommended first run)
  python3 gworkspace-drive-audit.py --mode both             # Shared drives + My Drive per-user
  python3 gworkspace-drive-audit.py --drive "Movement"     # Filter: only drives matching name
  python3 gworkspace-drive-audit.py --max-files 5000       # Cap files per drive (default: unlimited)
  python3 gworkspace-drive-audit.py --output-dir /tmp/out  # Custom output dir

DO NOT PASS --apply  (not implemented — this script is monitoring only)

Internal domains (not treated as external): yokly.gives, agapay.gives
"""

import argparse
import csv
import datetime
import json
import os
import re
import sys
import time
import unicodedata
import random
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────

SA_KEY       = os.environ.get("SA_KEY", "/keys/gam-project-gf5mq-97886701cbdd.json")
ADMIN_EMAIL  = os.environ.get("ADMIN_EMAIL", "brian.monte@yokly.gives")
CLIENT_DIR   = Path(os.environ.get("CLIENT_DIR", "/opt/monitoring"))
OUTPUT_DIR   = Path(os.environ.get("OUTPUT_DIR", "/opt/monitoring/reports/drive-audit"))
RUN_TS       = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

INTERNAL_DOMAINS = {"yokly.gives", "agapay.gives"}

# Google Drive ID regex patterns (per spec — treat matches as candidates only)
RE_DRIVE_FOLDER_URL = re.compile(r"/drive/folders/([A-Za-z0-9_-]{10,})")
RE_DRIVE_OPEN_ID    = re.compile(r"[?&]id=([A-Za-z0-9_-]{10,})")
RE_GENERIC_ID       = re.compile(r"\b([A-Za-z0-9_-]{20,})\b")
RE_JSON_DRIVE_FIELD = re.compile(
    r'"[^"]*(?:drive|shared_drive|sharedDrive|driveId|sharedDriveId)[^"]*"\s*:\s*"([A-Za-z0-9_-]{10,})"',
    re.IGNORECASE
)

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("ERROR: google-api-python-client not installed. Run: pip3 install google-api-python-client google-auth", file=sys.stderr)
    sys.exit(1)

SCOPES = [
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
]

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def normalize(s: str) -> str:
    """Lowercase, strip accents, remove non-alphanumeric, collapse spaces."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = re.sub(r"[^a-z0-9 ]", " ", s.lower())
    return re.sub(r"\s+", " ", s).strip()

def is_external(email_or_domain: str) -> bool:
    """Return True if this email/domain is outside the org."""
    if not email_or_domain:
        return False
    val = email_or_domain.strip().lower()
    # domain permission (e.g. "example.com")
    if "@" not in val:
        return val not in INTERNAL_DOMAINS
    domain = val.split("@", 1)[1]
    return domain not in INTERNAL_DOMAINS

def email_domain(email: str) -> str:
    if email and "@" in email:
        return email.split("@", 1)[1].lower()
    return ""

def api_retry(req, max_tries=4):
    for attempt in range(1, max_tries + 1):
        try:
            return req.execute(num_retries=2)
        except HttpError as e:
            status = getattr(e.resp, "status", None)
            if status in (429, 500, 502, 503, 504) and attempt < max_tries:
                wait = min(2 ** attempt, 30) + random.random()
                print(f"    Rate limit / server error ({status}), retrying in {wait:.1f}s...")
                time.sleep(wait)
                continue
            raise

def write_csv(path: Path, rows: list[dict], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"  Wrote {len(rows)} rows → {path}")

# ──────────────────────────────────────────────────────────────────────────────
# 1. Client Registry
# ──────────────────────────────────────────────────────────────────────────────

def load_client_registry() -> list[dict]:
    """
    Load all clients from clients_2026-*.json files in CLIENT_DIR.
    Deduplicates by display_name. Returns normalized list.
    """
    raw = []
    client_files = sorted(CLIENT_DIR.glob("clients_2026-*.json"))
    if not client_files:
        print(f"WARNING: No clients_2026-*.json files found in {CLIENT_DIR}", file=sys.stderr)
        return []

    for fp in client_files:
        data = json.loads(fp.read_text(encoding="utf-8"))
        records = data if isinstance(data, list) else [data]
        raw.extend(records)
        print(f"  Loaded {len(records)} clients from {fp.name}")

    # Deduplicate by display_name (case-insensitive)
    seen = {}
    for r in raw:
        key = normalize(r.get("display_name", "") or r.get("business_name", ""))
        if key and key not in seen:
            # Normalise assigned_agents to list of dicts
            agents = r.get("assigned_agents", [])
            if isinstance(agents, list):
                agent_emails = [a.get("email", "") for a in agents if isinstance(a, dict)]
                agent_names  = [a.get("name", "")  for a in agents if isinstance(a, dict)]
            else:
                agent_emails = []
                agent_names  = []

            client_emails = r.get("client_emails", [])
            if isinstance(client_emails, str):
                client_emails = [client_emails]

            seen[key] = {
                "display_name":    r.get("display_name", "").strip(),
                "business_name":   r.get("business_name", "").strip(),
                "client_name":     r.get("client_name", "").strip(),
                "account_category":r.get("account_category", "").strip(),
                "team_leader":     r.get("team_leader", "").strip(),
                "status":          r.get("status", "Active").strip(),
                "client_emails":   client_emails,
                "assigned_agents": agent_names,
                "agent_emails":    agent_emails,
                "total_agents":    r.get("total_agents", 0),
                # derived for matching
                "_norm_display":   normalize(r.get("display_name", "")),
                "_norm_business":  normalize(r.get("business_name", "")),
                "_norm_client":    normalize(r.get("client_name", "")),
                "_client_domains": list({email_domain(e) for e in client_emails if "@" in e}),
            }

    clients = list(seen.values())
    print(f"  Total unique clients: {len(clients)}")
    return clients

def match_drive_to_client(drive_name: str, clients: list[dict]) -> tuple[dict | None, str]:
    """
    Try to match a shared drive name to a client.
    Returns (client_dict, match_method) or (None, "no_match").

    Match methods (in priority order):
      exact       — normalized drive name == normalized display/business/client name
      prefix      — drive name is the beginning of display/business name (or vice versa)
      contains    — drive name is contained in display/business name (or vice versa)
      client_name — drive name matches the client_name field
      alias       — drive name matches a person-name part of display_name
    """
    dn = normalize(drive_name)
    if not dn:
        return None, "no_match"

    # Build tokens for the drive name (words)
    dn_words = set(dn.split())

    for c in clients:
        nd = c["_norm_display"]
        nb = c["_norm_business"]
        nc = c["_norm_client"]

        # 1. Exact
        if dn in (nd, nb, nc):
            method = "exact"
            if dn == nd: method = "exact"
            elif dn == nb: method = "exact_business"
            else: method = "exact_client_name"
            return c, method

        # 2. Drive name is fully contained in display/business name or vice versa
        # e.g. "Farmd Out" in "Farmd Out — Martita Mestey"
        if dn and nd and (dn in nd or nd in dn):
            return c, "prefix" if nd.startswith(dn) or dn.startswith(nd) else "contains"
        if dn and nb and (dn in nb or nb in dn):
            return c, "contains_business"

        # 3. client_name field match (e.g. drive "Craig Kabrhel" ↔ client_name "Craig Kabrhel")
        if nc and (dn == nc or dn in nc or nc in dn):
            return c, "client_name"

    # Second pass: alias / abbreviation matches (looser)
    for c in clients:
        nd = c["_norm_display"]

        # Abbreviation: e.g. "RZM" might be "Ricky Zollinger Media"
        words = nd.split()
        initials = "".join(w[0] for w in words if w)
        if dn == initials and len(dn) >= 2:
            return c, "alias_abbreviation"

        # Drive name words are a significant subset of display_name words
        dn_w = set(dn.split())
        nd_w = set(nd.split())
        if len(dn_w) >= 2 and dn_w <= nd_w:
            return c, "alias_word_subset"

        # Drive name contains person name from display (after the dash)
        if " — " in c["display_name"]:
            person_part = normalize(c["display_name"].split(" — ", 1)[1])
            if dn and person_part and (dn in person_part or person_part in dn):
                return c, "alias_person_name"

    return None, "no_match"

# ──────────────────────────────────────────────────────────────────────────────
# 2. Shared Drive Discovery & Permission Scan
# ──────────────────────────────────────────────────────────────────────────────

def list_all_shared_drives(drive_svc) -> list[dict]:
    """Return list of {id, name} for all shared drives visible to the SA."""
    drives = []
    pt = None
    while True:
        resp = api_retry(drive_svc.drives().list(
            pageSize=100, pageToken=pt,
            fields="nextPageToken,drives(id,name)"
        ))
        drives.extend(resp.get("drives", []))
        pt = resp.get("nextPageToken")
        if not pt:
            break
    return drives

def scan_shared_drive(drive_svc, drive_id: str, drive_name: str,
                      max_files: int | None = None) -> list[dict]:
    """
    List all files in a Shared Drive and return those with external permissions.
    Returns list of raw file dicts (id, name, mimeType, webViewLink, owners, permissions, parents).
    """
    findings = []
    total = 0
    pt = None

    while True:
        try:
            resp = api_retry(drive_svc.files().list(
                driveId=drive_id,
                includeItemsFromAllDrives=True,
                supportsAllDrives=True,
                corpora="drive",
                pageSize=100,
                pageToken=pt,
                fields=(
                    "nextPageToken,"
                    "files(id,name,mimeType,webViewLink,owners,"
                    "permissions(id,type,role,emailAddress,domain,allowFileDiscovery,expirationTime),"
                    "parents)"
                )
            ))
        except HttpError as e:
            print(f"    ERROR scanning drive {drive_name}: {e}", file=sys.stderr)
            break

        for f in resp.get("files", []):
            total += 1
            perms = f.get("permissions", [])
            for p in perms:
                ptype  = p.get("type", "")
                pemail = p.get("emailAddress", "")
                pdomain = p.get("domain", "")

                if ptype == "anyone":
                    findings.append((f, p))
                    break
                elif ptype in ("user", "group") and is_external(pemail):
                    findings.append((f, p))
                    break
                elif ptype == "domain" and is_external(pdomain):
                    findings.append((f, p))
                    break

        pt = resp.get("nextPageToken")
        if not pt:
            break
        if max_files and total >= max_files:
            print(f"    ⚠ Reached max-files limit ({max_files}) for drive '{drive_name}' — use --max-files 0 for full scan")
            break

    return findings, total

def scan_my_drive_for_user(drive_svc_for_user, user_email: str,
                           max_files: int | None = None) -> list[tuple]:
    """
    Scan a user's My Drive for externally-shared files.
    drive_svc_for_user should be built with creds delegated to user_email.
    Returns list of (file_dict, permission_dict).
    """
    findings = []
    total = 0
    pt = None

    while True:
        try:
            resp = api_retry(drive_svc_for_user.files().list(
                corpora="user",
                includeItemsFromAllDrives=False,
                pageSize=100,
                pageToken=pt,
                fields=(
                    "nextPageToken,"
                    "files(id,name,mimeType,webViewLink,owners,"
                    "permissions(id,type,role,emailAddress,domain,allowFileDiscovery),"
                    "parents,driveId)"
                )
            ))
        except HttpError as e:
            print(f"    ERROR scanning My Drive for {user_email}: {e}", file=sys.stderr)
            break

        for f in resp.get("files", []):
            total += 1
            # Skip files in shared drives (they'll be caught by the shared drive scan)
            if f.get("driveId"):
                continue
            perms = f.get("permissions", [])
            for p in perms:
                ptype  = p.get("type", "")
                pemail = p.get("emailAddress", "")
                pdomain = p.get("domain", "")
                if ptype == "anyone":
                    findings.append((f, p))
                    break
                elif ptype in ("user", "group") and is_external(pemail):
                    findings.append((f, p))
                    break
                elif ptype == "domain" and is_external(pdomain):
                    findings.append((f, p))
                    break

        pt = resp.get("nextPageToken")
        if not pt:
            break
        if max_files and total >= max_files:
            print(f"    ⚠ Reached max-files limit ({max_files}) for {user_email} My Drive")
            break

    return findings, total

# ──────────────────────────────────────────────────────────────────────────────
# 3. Classification
# ──────────────────────────────────────────────────────────────────────────────

def classify_finding(f: dict, p: dict, drive_scope: str,
                     matched_client: dict | None,
                     approved_drive_ids: set) -> tuple[str, str, str]:
    """
    Returns (classification, reason, recommended_action).

    drive_scope: "approved_shared_drive" | "unapproved_shared_drive" | "my_drive" | "unknown"
    """
    ptype   = p.get("type", "")
    prole   = p.get("role", "")
    pemail  = p.get("emailAddress", "").strip().lower()
    pdomain = p.get("domain", "").strip().lower()
    allow_discovery = p.get("allowFileDiscovery", False)

    # Anyone / public link — highest risk regardless of location
    if ptype == "anyone":
        link_type = "public (discoverable)" if allow_discovery else "anyone with link"
        if drive_scope == "approved_shared_drive":
            return (
                "Review — Anyone link in approved client drive",
                f"{link_type}, role={prole}, in approved client Shared Drive",
                "Confirm this public link is intentional for client; consider restricting to specific emails"
            )
        elif drive_scope == "my_drive":
            return (
                "Violation — Public link from My Drive",
                f"{link_type}, role={prole}, in My Drive (policy: restrict My Drive external sharing)",
                "Remove public link; migrate file to approved client Shared Drive if needed"
            )
        else:
            return (
                "Violation — Anyone/public link outside approved policy",
                f"{link_type}, role={prole}, in {drive_scope}",
                "Remove public link or move file to approved client Shared Drive"
            )

    # Specific external user / group / domain
    external_target = pemail or pdomain

    if drive_scope == "approved_shared_drive" and matched_client:
        # Check if this external email matches the client's known contacts
        client_emails_lower  = {e.strip().lower() for e in matched_client.get("client_emails", [])}
        client_domains_lower = set(matched_client.get("_client_domains", []))
        target_domain = email_domain(pemail) if pemail else pdomain.lower()

        if pemail in client_emails_lower or target_domain in client_domains_lower:
            return (
                "Allowed — Known Client Email/Domain",
                f"External {ptype} ({external_target}, role={prole}) matches client registry for '{matched_client['display_name']}'",
                "No action required"
            )
        else:
            return (
                "Review — Approved Shared Drive but unknown external recipient",
                f"External {ptype} ({external_target}, role={prole}) in approved client drive '{matched_client['display_name']}' but email/domain not in client registry",
                "Verify: is this a known client contact? If yes, add to client registry. If no, revoke."
            )

    elif drive_scope == "approved_shared_drive" and not matched_client:
        # Drive is approved but no client record — shouldn't happen but handle it
        return (
            "Review — Approved drive, client record missing",
            f"External {ptype} ({external_target}, role={prole}); drive is approved but client data unavailable",
            "Re-run after refreshing client registry"
        )

    elif drive_scope == "unapproved_shared_drive":
        return (
            "Violation — External sharing outside approved Shared Drive",
            f"External {ptype} ({external_target}, role={prole}) in Shared Drive not matched to any client",
            "Determine if drive should be a client drive and add to registry, or revoke external access"
        )

    elif drive_scope == "my_drive":
        return (
            "Review — My Drive external share",
            f"External {ptype} ({external_target}, role={prole}) in My Drive (policy: My Drive not auto-approved for external sharing)",
            "Migrate file to approved client Shared Drive if for client work; otherwise revoke"
        )

    else:
        return (
            "Unknown — Could not resolve parent drive",
            f"External {ptype} ({external_target}, role={prole}); drive scope unknown",
            "Investigate file location manually"
        )

# ──────────────────────────────────────────────────────────────────────────────
# 4. Drive ID candidate extraction
# ──────────────────────────────────────────────────────────────────────────────

def extract_drive_id_candidates(text: str) -> list[tuple[str, str]]:
    """
    Extract candidate Drive/Shared Drive IDs from arbitrary text.
    Returns list of (candidate_id, pattern_name).
    These are CANDIDATES only — must be validated via Drive API before trusting.
    """
    found = []
    for m in RE_DRIVE_FOLDER_URL.finditer(text):
        found.append((m.group(1), "drive_folder_url"))
    for m in RE_DRIVE_OPEN_ID.finditer(text):
        found.append((m.group(1), "open_id_param"))
    for m in RE_JSON_DRIVE_FIELD.finditer(text):
        found.append((m.group(1), "json_drive_field"))
    # Generic 20+ char token — lowest confidence, last pass
    generic = {m.group(1) for m in RE_GENERIC_ID.finditer(text)}
    # Remove already-found IDs
    already = {x[0] for x in found}
    for g in sorted(generic - already):
        found.append((g, "generic_20char_token"))
    return found

# ──────────────────────────────────────────────────────────────────────────────
# 5. Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Google Drive External Sharing Audit — dry-run / reporting only"
    )
    parser.add_argument("--mode",        choices=["shared-drives", "my-drive", "both"],
                        default="shared-drives",
                        help="Scan scope (default: shared-drives)")
    parser.add_argument("--output-dir",  default=str(OUTPUT_DIR),
                        help=f"Report output directory (default: {OUTPUT_DIR})")
    parser.add_argument("--drive",       default="",
                        help="Only scan shared drives whose name contains this substring")
    parser.add_argument("--max-files",   type=int, default=0,
                        help="Max files to scan per drive (0 = unlimited, default: 0)")
    parser.add_argument("--apply",       action="store_true",
                        help="(not implemented) Reserved for future remediation mode")
    args = parser.parse_args()

    if args.apply:
        print("ERROR: --apply is not implemented. This script is monitoring/reporting only.", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output_dir)
    max_files = args.max_files if args.max_files > 0 else None

    print("=" * 60)
    print("Google Drive External Sharing Audit")
    print(f"Run time : {RUN_TS}")
    print(f"SA key   : {SA_KEY}")
    print(f"Admin    : {ADMIN_EMAIL}")
    print(f"Mode     : {args.mode}")
    print(f"Output   : {out_dir}")
    if max_files:
        print(f"Max files: {max_files} per drive")
    print("DRY RUN  : no permissions will be modified")
    print("=" * 60)

    # ── Auth ──────────────────────────────────────────────────────────────────
    try:
        creds = service_account.Credentials.from_service_account_file(
            SA_KEY, scopes=SCOPES, subject=ADMIN_EMAIL
        )
    except Exception as e:
        print(f"ERROR: Auth failed: {e}", file=sys.stderr)
        sys.exit(1)

    drive_svc = build("drive", "v3", credentials=creds, cache_discovery=False)

    # ── Step 1: Client Registry ───────────────────────────────────────────────
    print("\n[1/5] Loading client registry...")
    clients = load_client_registry()
    if not clients:
        print("WARNING: No clients loaded — all drives will appear as unmatched.")

    # Write client_registry_normalized.csv
    reg_rows = []
    for c in sorted(clients, key=lambda x: x["display_name"]):
        reg_rows.append({
            "display_name":    c["display_name"],
            "business_name":   c["business_name"],
            "client_name":     c["client_name"],
            "account_category":c["account_category"],
            "team_leader":     c["team_leader"],
            "status":          c["status"],
            "client_emails":   "; ".join(c["client_emails"]),
            "assigned_agents": "; ".join(c["assigned_agents"]),
            "total_agents":    c["total_agents"],
        })
    write_csv(out_dir / "client_registry_normalized.csv", reg_rows, [
        "display_name","business_name","client_name","account_category",
        "team_leader","status","client_emails","assigned_agents","total_agents"
    ])

    # ── Step 2: Discover Shared Drives ───────────────────────────────────────
    print("\n[2/5] Discovering shared drives...")
    all_drives = list_all_shared_drives(drive_svc)
    print(f"  Found {len(all_drives)} shared drives")

    if args.drive:
        filtered = [d for d in all_drives if args.drive.lower() in d["name"].lower()]
        print(f"  Filtered to {len(filtered)} drives matching '{args.drive}'")
        all_drives = filtered

    # ── Step 3: Match drives to clients ──────────────────────────────────────
    print("\n[3/5] Matching shared drives to client registry...")
    approved_drives = []      # list of approved drive dicts
    unmatched_drives = []
    drive_approval_map = {}   # drive_id → {client, method}

    for drv in all_drives:
        drv_id   = drv["id"]
        drv_name = drv["name"]
        client, method = match_drive_to_client(drv_name, clients)
        if client:
            print(f"  ✓ MATCH  [{method:25s}] '{drv_name}' → '{client['display_name']}'")
            approved_drives.append({
                "shared_drive_id":           drv_id,
                "shared_drive_name":         drv_name,
                "client_display_name":       client["display_name"],
                "team_leader":               client["team_leader"],
                "match_method":              method,
                "client_emails":             "; ".join(client["client_emails"]),
                "assigned_agents":           "; ".join(client["assigned_agents"]),
                "approval_status":           "approved_external_sharing",
            })
            drive_approval_map[drv_id] = {"client": client, "method": method}
        else:
            print(f"  ✗ NOMATCH                             '{drv_name}'")
            unmatched_drives.append({
                "shared_drive_id":     drv_id,
                "shared_drive_name":   drv_name,
                "reason_not_matched":  "No client in registry matched this drive name",
                "suggested_client_match": _suggest_fuzzy(drv_name, clients),
                "needs_review":        "yes",
            })

    approved_ids = {d["shared_drive_id"] for d in approved_drives}
    print(f"\n  Approved client drives : {len(approved_drives)}")
    print(f"  Unmatched drives       : {len(unmatched_drives)}")

    write_csv(out_dir / "approved_client_shared_drives.csv", approved_drives, [
        "shared_drive_id","shared_drive_name","client_display_name",
        "team_leader","match_method","client_emails","assigned_agents","approval_status"
    ])
    write_csv(out_dir / "unmatched_shared_drives.csv", unmatched_drives, [
        "shared_drive_id","shared_drive_name","reason_not_matched",
        "suggested_client_match","needs_review"
    ])

    # ── Step 4: External sharing scan ────────────────────────────────────────
    print("\n[4/5] Scanning for external sharing...")
    all_findings = []

    # 4a. Shared Drives
    for drv in all_drives:
        drv_id   = drv["id"]
        drv_name = drv["name"]
        is_approved = drv_id in approved_ids
        scope = "approved_shared_drive" if is_approved else "unapproved_shared_drive"
        client_rec = drive_approval_map.get(drv_id, {}).get("client") if is_approved else None

        print(f"  Scanning '{drv_name}' ({scope})...")
        try:
            file_findings, file_total = scan_shared_drive(
                drive_svc, drv_id, drv_name, max_files=max_files
            )
        except Exception as e:
            print(f"    ERROR: {e}", file=sys.stderr)
            continue

        print(f"    {file_total} files scanned, {len(file_findings)} with external permissions")

        for (f, p) in file_findings:
            classification, reason, action = classify_finding(
                f, p, scope, client_rec, approved_ids
            )
            owner_email = ""
            owners = f.get("owners", [])
            if owners:
                owner_email = owners[0].get("emailAddress", "")

            all_findings.append({
                "file_id":                 f.get("id", ""),
                "file_name":               f.get("name", ""),
                "mime_type":               f.get("mimeType", ""),
                "web_view_link":           f.get("webViewLink", ""),
                "owner_email":             owner_email,
                "drive_scope":             scope,
                "shared_drive_id":         drv_id,
                "shared_drive_name":       drv_name,
                "matched_client":          client_rec["display_name"] if client_rec else "",
                "permission_type":         p.get("type", ""),
                "permission_role":         p.get("role", ""),
                "external_email_or_domain":p.get("emailAddress", "") or p.get("domain", ""),
                "allow_file_discovery":    p.get("allowFileDiscovery", False),
                "permission_expiration":   p.get("expirationTime", ""),
                "classification":          classification,
                "reason":                  reason,
                "recommended_action":      action,
            })

    # 4b. My Drive (optional)
    if args.mode in ("my-drive", "both"):
        print("\n  Scanning My Drive for all users...")
        try:
            dir_svc = build("admin", "directory_v1", credentials=creds, cache_discovery=False)
            users_resp = dir_svc.users().list(customer="my_customer", maxResults=500,
                                               fields="users(primaryEmail,suspended)").execute()
            all_users = [u for u in users_resp.get("users", []) if not u.get("suspended")]
        except Exception as e:
            print(f"  ERROR fetching user list: {e}", file=sys.stderr)
            all_users = []

        print(f"  {len(all_users)} active users to scan")

        for user in all_users:
            uemail = user["primaryEmail"]
            print(f"    My Drive: {uemail}", end="", flush=True)
            try:
                user_creds = service_account.Credentials.from_service_account_file(
                    SA_KEY, scopes=SCOPES, subject=uemail
                )
                user_drive = build("drive", "v3", credentials=user_creds, cache_discovery=False)
                file_findings, file_total = scan_my_drive_for_user(
                    user_drive, uemail, max_files=max_files
                )
                print(f" — {file_total} files, {len(file_findings)} external")
            except Exception as e:
                print(f" — ERROR: {e}", file=sys.stderr)
                continue

            for (f, p) in file_findings:
                classification, reason, action = classify_finding(
                    f, p, "my_drive", None, approved_ids
                )
                all_findings.append({
                    "file_id":                 f.get("id", ""),
                    "file_name":               f.get("name", ""),
                    "mime_type":               f.get("mimeType", ""),
                    "web_view_link":           f.get("webViewLink", ""),
                    "owner_email":             uemail,
                    "drive_scope":             "my_drive",
                    "shared_drive_id":         "",
                    "shared_drive_name":       "",
                    "matched_client":          "",
                    "permission_type":         p.get("type", ""),
                    "permission_role":         p.get("role", ""),
                    "external_email_or_domain":p.get("emailAddress", "") or p.get("domain", ""),
                    "allow_file_discovery":    p.get("allowFileDiscovery", False),
                    "permission_expiration":   p.get("expirationTime", ""),
                    "classification":          classification,
                    "reason":                  reason,
                    "recommended_action":      action,
                })

    # ── Step 5: Write findings report ─────────────────────────────────────────
    print("\n[5/5] Writing reports...")

    findings_fieldnames = [
        "file_id","file_name","mime_type","web_view_link","owner_email",
        "drive_scope","shared_drive_id","shared_drive_name","matched_client",
        "permission_type","permission_role","external_email_or_domain",
        "allow_file_discovery","permission_expiration",
        "classification","reason","recommended_action",
    ]
    write_csv(out_dir / "external_sharing_findings.csv", all_findings, findings_fieldnames)

    # Summary
    print("\n── Summary ────────────────────────────────────────")
    from collections import Counter
    by_class = Counter(r["classification"] for r in all_findings)
    for cls, n in sorted(by_class.items(), key=lambda x: -x[1]):
        print(f"  {n:4d}  {cls}")
    print(f"\n  Total external-sharing findings: {len(all_findings)}")
    print(f"  Reports written to: {out_dir}/")
    print(f"\n  ⚠ DRY RUN — no permissions were modified.")
    print("────────────────────────────────────────────────────")


def _suggest_fuzzy(drive_name: str, clients: list[dict]) -> str:
    """Simple best-guess suggestion when no match found."""
    dn = normalize(drive_name)
    dn_words = set(dn.split()) - {"and", "the", "of", "a", "an", "for", "inc", "llc"}
    best = None
    best_score = 0
    for c in clients:
        nd_words = set(c["_norm_display"].split())
        overlap = len(dn_words & nd_words)
        if overlap > best_score:
            best_score = overlap
            best = c["display_name"]
    return best or ""


if __name__ == "__main__":
    main()
