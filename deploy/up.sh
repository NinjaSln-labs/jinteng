#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/deploy"
COMPOSE=(docker compose -f "$DEPLOY/docker-compose.yml")

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker not found" >&2
  exit 1
fi

mkdir -p "$DEPLOY/secrets"
PASS="$DEPLOY/secrets/master.pass"
if [[ ! -f "$PASS" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24 >"$PASS"
  else
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$PASS"
    echo >>"$PASS"
  fi
  chmod 600 "$PASS"
  echo "created $PASS (keep private; do not commit)"
fi

echo "building & starting..."
"${COMPOSE[@]}" build
"${COMPOSE[@]}" up -d

echo -n "waiting for healthz"
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
    echo " ok"
    break
  fi
  echo -n "."
  sleep 0.5
done

if ! curl -sf http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
  echo
  echo "error: service not healthy; logs:" >&2
  "${COMPOSE[@]}" logs --tail=80 jinteng >&2 || true
  exit 1
fi

TOKEN="$("${COMPOSE[@]}" exec -T jinteng cat /data/token | tr -d '\r\n')"
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -z "${LAN_IP}" ]] && LAN_IP="<your-lan-ip>"

cat <<EOF

======= jinteng is up =======
Docs page : http://127.0.0.1:8787/          ← 浏览器打开看对接说明
Local API : http://127.0.0.1:8787
LAN URL   : http://${LAN_IP}:8787
            (compose currently binds 127.0.0.1 only —
             edit deploy/docker-compose.yml ports to "8787:8787" for LAN)

API Token :
  ${TOKEN}

Client env (this machine):
  export JINTENG_URL=http://127.0.0.1:8787
  export JINTENG_TOKEN='${TOKEN}'

Repo docs:
  docs/docker-local.md
  docs/client.md
============================
EOF
