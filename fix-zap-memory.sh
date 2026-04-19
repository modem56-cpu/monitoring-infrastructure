#!/usr/bin/env bash
# fix-zap-memory.sh
# Recreates the owasp-zap container with proper memory constraints.
#
# Problem: ZAP auto-sizes JVM heap to 1/4 of host RAM at startup (~1985 MB on
# this 7.8 GB host). It doesn't read the Docker cgroup limit. This causes ZAP
# to swap heavily and contribute to the swap pressure crisis.
#
# Fix: inject a .ZAP_JVM.properties file that explicitly sets -Xmx384m, and
# set the Docker memory limit to 700m (heap 384m + ~300m JVM off-heap overhead).
#
# Run as root.
set -euo pipefail

CONTAINER="owasp-zap"
DOCKER_MEM="700m"
JVM_HEAP="384m"

echo "=== Recreating $CONTAINER: Docker limit=${DOCKER_MEM}, JVM heap=${JVM_HEAP} ==="
echo ""

if ! docker inspect "$CONTAINER" &>/dev/null; then
  echo "ERROR: container $CONTAINER not found"
  exit 1
fi

echo "Stopping $CONTAINER..."
docker stop "$CONTAINER"

echo "Removing $CONTAINER..."
docker rm "$CONTAINER"

echo "Starting $CONTAINER with --memory $DOCKER_MEM..."
docker run -d \
  --name owasp-zap \
  --restart unless-stopped \
  --memory "$DOCKER_MEM" \
  --memory-swap "$DOCKER_MEM" \
  -p 8080:8080 \
  -p 8090:8090 \
  zaproxy/zap-stable \
  zap.sh -daemon \
    -host 0.0.0.0 \
    -port 8080 \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true

echo ""
echo "Injecting JVM heap cap ($JVM_HEAP) into container..."
# Wait briefly for container filesystem to be ready
sleep 2
docker exec owasp-zap bash -c "
  mkdir -p /home/zap/.ZAP
  echo '-Xmx${JVM_HEAP}' > /home/zap/.ZAP/.ZAP_JVM.properties
  echo '-Xms128m' >> /home/zap/.ZAP/.ZAP_JVM.properties
  chown zap:zap /home/zap/.ZAP /home/zap/.ZAP/.ZAP_JVM.properties
  echo '  JVM properties written:'
  cat /home/zap/.ZAP/.ZAP_JVM.properties
"

# The properties file only takes effect on next ZAP restart — restart now
echo ""
echo "Restarting ZAP to pick up JVM properties..."
docker restart owasp-zap

echo ""
echo "Waiting for ZAP to become healthy..."
for i in $(seq 1 30); do
  sleep 3
  status=$(docker inspect --format='{{.State.Health.Status}}' owasp-zap 2>/dev/null || echo "unknown")
  echo "  [$i] $status"
  if [ "$status" = "healthy" ]; then
    break
  fi
done

echo ""
echo "Verifying JVM heap flag:"
docker exec owasp-zap ps aux | grep java | grep -v grep | grep -oP '\-Xmx\S+'

echo ""
echo "Memory stats:"
docker stats --no-stream owasp-zap

echo ""
echo "Done."
echo "  JVM heap cap : $JVM_HEAP  (was -Xmx1985m)"
echo "  Docker limit : $DOCKER_MEM  (was unlimited)"
echo "  Expected usage: ~300-450 MiB at rest"
