#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

if [ -f ".venv/bin/activate" ]; then
  source .venv/bin/activate
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[docker] docker introuvable"
  exit 1
fi

container_name="test_sshd"
host_port="2222"

docker rm -f "$container_name" >/dev/null 2>&1 || true

echo "[docker] démarrage SSH de test..."

if docker run -d -p "${host_port}:22" --name "$container_name" rastasheep/ubuntu-sshd:18.04 >/dev/null 2>&1; then
  echo "[docker] image rastasheep OK (22 -> ${host_port})"
else
  echo "[docker] fallback: linuxserver/openssh-server (multi-arch)"
  docker run -d \
    --name "$container_name" \
    -p "${host_port}:2222" \
    -e PUID=1000 \
    -e PGID=1000 \
    -e PASSWORD_ACCESS=true \
    -e USER_PASSWORD=pass1234 \
    -e USER_NAME=test \
    ghcr.io/linuxserver/openssh-server:latest >/dev/null
  echo "[docker] image linuxserver OK (2222 -> ${host_port})"
fi

sleep 2

out_json="tests/scan_test_ssh.json"
echo "[scan] 127.0.0.1:${host_port}"
python3 scanner.py -t 127.0.0.1 -p "${host_port}" --show-open --json "$out_json" --db

python3 - <<'PY'
import json

with open("tests/scan_test_ssh.json", "r", encoding="utf-8") as f:
    d = json.load(f)

opens = [r for r in d.get("results", []) if r.get("state") == "open"]
print("[scan] open ports:", [r.get("port") for r in opens])

for r in d.get("results", []):
    if r.get("port") == 2222:
        banner = (r.get("banner") or "")[:300]
        print("[scan] service:", r.get("service"))
        print("[scan] banner:", banner)
PY

echo "[docker] nettoyage"
docker rm -f "$container_name" >/dev/null 2>&1 || true
echo "[done]"
