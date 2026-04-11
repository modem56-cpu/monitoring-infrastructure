#!/usr/bin/env bash
set -euo pipefail
exec /opt/monitoring/prom_refresh_dashboards.sh "$@"
