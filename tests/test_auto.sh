#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi

echo "[test] HTTP (python -m http.server 8000)"
python3 -m http.server 8000 >/tmp/http_server.log 2>&1 &
http_pid=$!
sleep 0.6

out_json="tests/scan_test_8000.json"
python3 scanner.py -t 127.0.0.1 -p 8000 --show-open --json "$out_json" --db

python3 - <<'PY'
import json

with open("tests/scan_test_8000.json", "r", encoding="utf-8") as f:
    d = json.load(f)

opens = [r for r in d.get("results", []) if r.get("state") == "open"]
print("[http] open ports:", [r.get("port") for r in opens])
PY

kill "$http_pid" >/dev/null 2>&1 || true
echo "[test] HTTP OK"

if command -v docker >/dev/null 2>&1; then
  echo "[test] SSH (docker)"
  bash tests/test_auto_docker.sh
else
  echo "[test] docker absent, test SSH ignoré"
fi

echo "[test] terminé"
