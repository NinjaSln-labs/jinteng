#!/bin/sh
set -eu

DIR="${JINTENG_DIR:-/data}"
mkdir -p "$DIR"

if [ ! -f "$DIR/jinteng.bin" ]; then
  echo "jinteng: no jinteng.bin — initializing under $DIR"
  if [ -z "${JINTENG_PASSWORD:-}" ] && [ -z "${JINTENG_PASSWORD_FILE:-}" ]; then
    echo "error: set JINTENG_PASSWORD_FILE (or JINTENG_PASSWORD) before first boot" >&2
    exit 1
  fi
  jinteng init --dir "$DIR"
  echo "jinteng: init done. API token is in $DIR/token"
fi

exec jinteng serve --listen "${JINTENG_LISTEN:-0.0.0.0:8787}"
