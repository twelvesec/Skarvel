#!/bin/sh
# Builds static, dependency-free skarvel binaries into bin/.
#   scripts/build.sh          host platform only
#   scripts/build.sh all      linux/macOS/windows on amd64 and arm64
set -eu
cd "$(dirname "$0")/.."

build() {
	out="bin/skarvel-$1-$2"
	[ "$1" = windows ] && out="$out.exe"
	CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/skarvel
	echo "built $out"
}

if [ "${1:-}" = all ]; then
	for os in linux darwin windows; do
		for arch in amd64 arm64; do build "$os" "$arch"; done
	done
else
	build "$(go env GOOS)" "$(go env GOARCH)"
fi
