#!/usr/bin/env bash
set -euo pipefail
TS="$(date +%F_%H%M%S)"

# Search where the old metric names are referenced
mapfile -t FILES < <(sudo grep -RIlE 'sys_topproc_(cpu_percent|mem_percent)' \
  /opt/monitoring/bin /opt/monitoring 2>/dev/null || true)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "OK: No scripts reference sys_topproc_pcpu_percent/sys_topproc_pmem_percent"
  exit 0
fi

echo "Patching these files:"
printf ' - %s\n' "${FILES[@]}"

for f in "${FILES[@]}"; do
  sudo cp -av "$f" "${f}.bak.${TS}"
  sudo perl -pi -e '
    s/sys_topproc_pcpu_percent/sys_topproc_pcpu_percent/g;
    s/sys_topproc_pmem_percent/sys_topproc_pmem_percent/g;
  ' "$f"
done

echo "OK: Patched CPU/MEM metric names in HTML generators."
