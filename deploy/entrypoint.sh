#!/bin/sh
set -eu

DIR="${LANVAULT_DIR:-/data}"
mkdir -p "$DIR"

if [ ! -f "$DIR/vault.bin" ]; then
  echo "lanvault: no vault.bin — initializing under $DIR"
  if [ -z "${LANVAULT_PASSWORD:-}" ] && [ -z "${LANVAULT_PASSWORD_FILE:-}" ]; then
    echo "error: set LANVAULT_PASSWORD_FILE (or LANVAULT_PASSWORD) before first boot" >&2
    exit 1
  fi
  lanvault init --dir "$DIR"
  echo "lanvault: init done. API token is in $DIR/token"
fi

exec lanvault serve --listen "${LANVAULT_LISTEN:-0.0.0.0:8787}"
