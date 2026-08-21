#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/dist"
mkdir -p "$OUT"

build() {
  local os="$1" arch="$2"
  local name="jinteng_${os}_${arch}"
  if [[ "$os" == "windows" ]]; then
    name="${name}.exe"
  fi
  echo "→ $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w" \
    -o "${OUT}/${name}" "${ROOT}/cmd/jinteng"
}

cd "$ROOT"
go mod tidy
build linux amd64
build linux arm64
build darwin amd64
build darwin arm64
build windows amd64
echo "artifacts in ${OUT}"
ls -lh "$OUT"
