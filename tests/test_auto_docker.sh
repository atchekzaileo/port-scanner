#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

# Activate venv if present
if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[docker] Docker not found"
  exit 1
fi

docker rm -f test_sshd >/dev/null 2>&1 || true

echo "[docker] Trying rastasheep/ubuntu-sshd:18.04 (may fail on Apple Silicon)..."
set +e
docker run -d -p 2222:22 --name test_sshd rastasheep/ubuntu-sshd:18.04 >/dev/null 2>&1
RC=$?
set -e

if [ $RC -ne 0 ]; then
  echo "[docker] Fallback: linuxserver/openssh-server (multi-arch)"
  docker run -d --name test_sshd -p 2222:2222 -e PUID=1000 -e PGID=1000 -e PASSWORD_ACCESS=true -e USER_PASSWORD=pass1234 -e USER_NAME=test ghcr.io/linuxserver/openssh-server:latest >/dev/null 2>&1
  echo "[docker] launched linuxserver openssh on 2222"
else
  echo "[docker] launched rastasheep image mapping 22->2222"
fi

sleep 2

echo "[scan] Scanning 127.0.0.1:2222"
python3 scanner.py -t 127.0.0.1 -p 2222 --show-open --json tests/scan_test_ssh.json --db

python3 - <<'PY'
import json
d=json.load(open('tests/scan_test_ssh.json'))
opens=[r for r in d['results'] if r['state']=='open']
print('[scan] Open ports:', [r['port'] for r in opens])
for r in d['results']:
    if r['port']==2222:
        print('[scan] service:', r.get('service'))
        print('[scan] banner:', (r.get('banner') or '')[:300])
PY

echo "[docker] cleaning up"
docker rm -f test_sshd >/dev/null 2>&1 || true
echo "[done]"
