#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/bin/jinteng"
DIR="${ROOT}/.jinteng-test"
rm -rf "$DIR"
export JINTENG_DIR="$DIR"
export JINTENG_PASSWORD='smoke-test-master-password-not-for-prod'

"$BIN" init >/tmp/jinteng-smoke-init.txt
"$BIN" set demo/key 'hello-secret'
"$BIN" set demo/other 'other-value'
got="$("$BIN" get demo/key)"
[[ "$got" == "hello-secret" ]] || { echo "get mismatch: $got"; exit 1; }
"$BIN" list | grep -q 'demo/key'
out="$("$BIN" run -e DEMO_KEY=demo/key -- /bin/sh -c 'printf %s "$DEMO_KEY"')"
[[ "$out" == "hello-secret" ]] || { echo "run mismatch: $out"; exit 1; }

# serve + remote client
"$BIN" serve --listen 127.0.0.1:18787 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:18787/healthz >/dev/null; then break; fi
  sleep 0.1
done
docs="$(curl -sf http://127.0.0.1:18787/)"
echo "$docs" | grep -q '金縢 对接说明' || { echo "docs page missing"; exit 1; }
if echo "$docs" | grep -q 'jt_'; then echo "docs page leaked token prefix"; exit 1; fi
export JINTENG_URL=http://127.0.0.1:18787
export JINTENG_TOKEN="$(cat "$DIR/token")"
remote_got="$(JINTENG_PASSWORD= "$BIN" get demo/key)"
[[ "$remote_got" == "hello-secret" ]] || { echo "remote get mismatch: $remote_got"; exit 1; }

echo "SMOKE OK"
rm -rf "$DIR"
