#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-dev}"
target_os="${2:-linux}"
target_arch="${3:-amd64}"
[[ "$version" =~ ^[a-zA-Z0-9][a-zA-Z0-9.+_-]*$ ]] || { echo 'Version must be a simple release label' >&2; exit 1; }
[[ "$target_os" =~ ^(windows|linux|darwin)$ && "$target_arch" =~ ^(amd64|arm64)$ ]] || { echo 'Unsupported release target' >&2; exit 1; }
commit="$(git rev-parse --short HEAD)"
export DRAFRP_BUILD_ID="$version+$commit"
(cd web && if [ "${SKIP_NPM_CI:-0}" != 1 ]; then npm ci --no-audit --no-fund; fi && npm run build)
rm -rf internal/webui/dist
mkdir -p internal/webui/dist
cp -R web/dist/. internal/webui/dist/
out="bin/$version/$target_os-$target_arch"
mkdir -p "$out"
suffix=''
if [ "$target_os" = windows ]; then suffix='.exe'; fi
for role in cloud edge client; do
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build -trimpath -tags release \
    -ldflags "-s -w -X drafrp/internal/buildinfo.Version=$version -X drafrp/internal/buildinfo.Commit=$commit" \
    -o "$out/drafrp-$role$suffix" "./cmd/drafrp-$role"
done
cp -R examples "$out/"
cp README.md IMPLEMENTATION.md API-CONTRACT.md "$out/"
(cd "$out" && sha256sum drafrp-* > SHA256SUMS)
printf '%s\n' "$out"
