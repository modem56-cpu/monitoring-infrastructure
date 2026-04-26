#!/usr/bin/env bash
# Update Google Workspace alert rules:
# - Replace always-on extshare alert with delta-based (fires only when count grows)
# - Add shared drive size alerts (per-drive thresholds)
# - Add user approaching 50GB quota alert
set -euo pipefail

cat > /opt/monitoring/rules/gworkspace.rules.yml << 'RULES'
groups:
- name: google_workspace
  rules:

  # --- Recording rule: snapshot unrestricted count every scrape ---
  # Used for delta detection — fires only when count GROWS, not just when > 0
  - record: gworkspace_extshare_unrestricted_users_baseline
    expr: gworkspace_extshare_unrestricted_users

  # Old "always-on" alert replaced by delta below — kept as info for dashboard only
  - alert: GWorkspace_ExtShare_Unrestricted_Info
    expr: gworkspace_extshare_unrestricted_users > 0
    for: 5m
    labels:
      severity: info
    annotations:
      summary: "{{ $value }} users in unrestricted OU (baseline — OU migration incomplete)"
      description: "Known state: users not yet moved to DEFAULT-BLOCKED OU. Actionable alert fires only when count increases."

  # Actionable: fires when count INCREASES (new user added to unrestricted pool)
  - alert: GWorkspace_ExtShare_UnrestrictedIncreased
    expr: gworkspace_extshare_unrestricted_users > (gworkspace_extshare_unrestricted_users offset 1h)
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Unrestricted external sharers increased — now {{ $value }} (up from 1h ago)"
      description: "A user was moved out of DEFAULT-BLOCKED OU or a new account was created without OU assignment."

  - alert: GWorkspace_ExtShare_ExceptionOU_Unauthorized
    expr: gworkspace_extshare_exception_unauthorized > 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "{{ $value }} UNAUTHORIZED user(s) in SHARED-DRIVES-EXTERNAL OU — delegate allowlist violation"

  - alert: GWorkspace_ExtShare_ExceptionOU_Authorized
    expr: gworkspace_extshare_exception_authorized > 0
    for: 4h
    labels:
      severity: info
    annotations:
      summary: "{{ $value }} authorized delegate(s) in SHARED-DRIVES-EXTERNAL OU for over 4h — should be temporary"

  - alert: GWorkspace_CollectorDown
    expr: gworkspace_collector_up == 0
    for: 10m
    labels:
      severity: critical
    annotations:
      summary: "Google Workspace collector is failing"

  - alert: GWorkspace_OverQuota
    expr: gworkspace_drive_users_over_quota > 0
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "{{ $value }} non-exempt users over 50GB storage quota"

  # --- User approaching 50GB quota (>40GB = 80% threshold) ---
  - alert: GWorkspace_UserApproachingQuota
    expr: gworkspace_drive_usage_bytes{exempt="false"} > 40 * 1024 * 1024 * 1024
    for: 30m
    labels:
      severity: warning
    annotations:
      summary: "{{ $labels.user }} is at {{ $value | humanize1024 }}B — approaching 50GB quota"
      description: "User is over 80% of the 50GB cap. Notify to clean up or request exemption."

  # --- Shared Drive size alerts ---
  # 1. Yokly USA already at 1.5TB — separate higher thresholds
  - alert: GWorkspace_SharedDrive_Large
    expr: gworkspace_shared_drive_size_bytes{drive!="1. Yokly USA"} > 100 * 1024 * 1024 * 1024
    for: 30m
    labels:
      severity: warning
    annotations:
      summary: "Shared Drive '{{ $labels.drive }}' is {{ $value | humanize1024 }}B — over 100GB"

  - alert: GWorkspace_SharedDrive_Critical
    expr: gworkspace_shared_drive_size_bytes{drive!="1. Yokly USA"} > 500 * 1024 * 1024 * 1024
    for: 30m
    labels:
      severity: critical
    annotations:
      summary: "Shared Drive '{{ $labels.drive }}' is {{ $value | humanize1024 }}B — over 500GB"

  - alert: GWorkspace_SharedDrive_YoklyUSA_Large
    expr: gworkspace_shared_drive_size_bytes{drive="1. Yokly USA"} > 1800 * 1024 * 1024 * 1024
    for: 30m
    labels:
      severity: warning
    annotations:
      summary: "'1. Yokly USA' shared drive is {{ $value | humanize1024 }}B — approaching 2TB"

  - alert: GWorkspace_SharedDrive_YoklyUSA_Critical
    expr: gworkspace_shared_drive_size_bytes{drive="1. Yokly USA"} > 2500 * 1024 * 1024 * 1024
    for: 30m
    labels:
      severity: critical
    annotations:
      summary: "'1. Yokly USA' shared drive is {{ $value | humanize1024 }}B — over 2.5TB"

  # --- Rapid growth: >10GB added to any shared drive in 1 hour ---
  - alert: GWorkspace_SharedDrive_RapidGrowth
    expr: increase(gworkspace_shared_drive_size_bytes[1h]) > 10 * 1024 * 1024 * 1024
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Shared Drive '{{ $labels.drive }}' grew by {{ $value | humanize1024 }}B in 1h — possible bulk upload"
RULES

echo "Rules written. Reloading Prometheus..."
curl -s -X POST http://127.0.0.1:9090/-/reload && echo "Prometheus reloaded OK"

echo ""
echo "Validating rules..."
docker exec prometheus promtool check rules /etc/prometheus/rules/gworkspace.rules.yml 2>&1

echo ""
echo "Done."
