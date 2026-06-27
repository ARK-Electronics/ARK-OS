#!/usr/bin/env bash
# Compose-free runner for the local test harness — works with a bare Docker engine
# (no compose plugin / buildx needed). Usage: bash test/run.sh {up|logs|down}
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NET=ark-os-test
APP=ark-os-test-app
CAM=ark-os-test-go2rtc
IMG=ark-os-test:latest

case "${1:-up}" in
  up)
    docker build -t "$IMG" -f "$ROOT/test/Dockerfile" "$ROOT"
    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"
    docker rm -f "$CAM" "$APP" >/dev/null 2>&1 || true

    # Synthetic camera. --network-alias go2rtc so the app's nginx can proxy to it.
    docker run -d --name "$CAM" --network "$NET" --network-alias go2rtc \
      -v "$ROOT/test/go2rtc.test.yaml:/config/go2rtc.yaml" \
      -p 8555:8555/tcp -p 8555:8555/udp \
      alexxit/go2rtc:latest

    # The userspace stack (managers + gateway + nginx + fake FC).
    docker run -d --name "$APP" --network "$NET" --init \
      -p 8080:80 \
      -v "$ROOT/test/manifests:/usr/lib/ark-os/manifests:ro" \
      -v "$ROOT/test/configs/mavlink-router.conf:/etc/ark-os/mavlink-router.conf" \
      -v "$ROOT/test/go2rtc.test.yaml:/etc/ark-os/go2rtc.yaml" \
      "$IMG"

    echo "ARK-OS test UI -> http://localhost:8080   (logs: bash test/run.sh logs)"
    ;;
  logs) docker logs -f "$APP" ;;
  down)
    docker rm -f "$APP" "$CAM" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    echo "stopped"
    ;;
  *) echo "usage: bash test/run.sh {up|logs|down}"; exit 1 ;;
esac
