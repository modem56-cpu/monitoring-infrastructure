#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:8082/api/v0/console/widget"
OUT="/opt/monitoring/logs/akvorado_mesh.jsonl"
TMP="$(mktemp)"
TS="$(date -Iseconds)"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
MAX_BYTES=$((50 * 1024 * 1024))

rotate_if_needed() {
  if [ -f "$OUT" ]; then
    local sz
    sz="$(stat -c %s "$OUT" 2>/dev/null || echo 0)"
    if [ "$sz" -gt "$MAX_BYTES" ]; then
      tail -n 5000 "$OUT" > "${OUT}.tmp"
      mv -f "${OUT}.tmp" "$OUT"
      chmod 664 "$OUT" || true
    fi
  fi
}

emit_json() {
  local widget="$1"
  local url="$2"

  if curl -fsS --max-time 20 "$url" > "$TMP"; then
    jq -c \
      --arg ts "$TS" \
      --arg host "$HOSTNAME_FQDN" \
      --arg widget "$widget" \
      '{
        mesh_component: "akvorado_widget",
        source: "akvorado",
        collector_host: $host,
        site: "Agapay",
        exporter_focus: "192.168.10.1",
        widget: $widget,
        fetched_at: $ts,
        payload: .
      }' < "$TMP" >> "$OUT"
  else
    jq -nc \
      --arg ts "$TS" \
      --arg host "$HOSTNAME_FQDN" \
      --arg widget "$widget" \
      '{
        mesh_component: "akvorado_widget_error",
        source: "akvorado",
        collector_host: $host,
        site: "Agapay",
        exporter_focus: "192.168.10.1",
        widget: $widget,
        fetched_at: $ts,
        error: "curl_failed"
      }' >> "$OUT"
  fi
}

rotate_if_needed

emit_json "flow-rate"   "${BASE_URL}/flow-rate"
emit_json "exporters"   "${BASE_URL}/exporters"
emit_json "flow-last"   "${BASE_URL}/flow-last"
emit_json "top-exporter" "${BASE_URL}/top/exporter"
emit_json "top-protocol" "${BASE_URL}/top/protocol"
emit_json "top-src-port" "${BASE_URL}/top/src-port"
emit_json "top-dst-port" "${BASE_URL}/top/dst-port"

chmod 664 "$OUT" || true
rm -f "$TMP"
