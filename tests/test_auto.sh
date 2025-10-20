#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

# Activate venv if exists
if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi

echo "[test_auto] --- TEST HTTP ---"
python3 -m http.server 8000 > /tmp/http_server.log 2>&1 &
HTTP_PID=$!
sleep 0.6
python3 scanner.py -t 127.0.0.1 -p 8000 --show-open --json tests/scan_test_8000.json --db
python3 - <<'PY'
import json
d=json.load(open('tests/scan_test_8000.json'))
opens=[r for r in d['results'] if r['state']=='open']
print('HTTP Open ports:', [r['port'] for r in opens])
PY
kill $HTTP_PID 2>/dev/null || true
echo "[test_auto] HTTP test done."

# Optional SSH test using Docker if available
if command -v docker >/dev/null 2>&1; then
  echo "[test_auto] --- TEST SSH via Docker (rastasheep/ubuntu-sshd) ---"
  docker run -d -p 2222:22 --name test_sshd rastasheep/ubuntu-sshd:18.04 > /dev/null || true
  sleep 1.5
  python3 scanner.py -t 127.0.0.1 -p 2222 --show-open --json tests/scan_test_ssh.json --db
  python3 - <<'PY'
import json
d=json.load(open('tests/scan_test_ssh.json'))
opens=[r for r in d['results'] if r['state']=='open']
print('SSH Open ports:', [r['port'] for r in opens])
for r in d['results']:
    if r['port']==2222:
        print('SSH banner/service:', r['service'], r['banner'][:300])
PY
  docker rm -f test_sshd >/dev/null 2>&1 || true
  echo "[test_auto] SSH test done."
else
  echo "[test_auto] Docker not found - skipping SSH test. To test SSH, either enable Remote Login (macOS) or run a container."
fi

echo "[test_auto] All done."
