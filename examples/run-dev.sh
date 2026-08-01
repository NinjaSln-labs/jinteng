#!/usr/bin/env bash
# Example: inject secrets into a command without writing .env
set -euo pipefail
exec lanvault run \
  -e OPENAI_API_KEY=openai/key \
  -e DATABASE_URL=db/url \
  -- "$@"
