#!/bin/sh
# Usage: IPSCANNER_KEY_FILE=key IPSCANNER_E2E_SITE_HELPER=site.cjs sh test/e2e/run.sh (KEEP=1 keeps containers)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${IPSCANNER_KEY_FILE:?set IPSCANNER_KEY_FILE}"
: "${IPSCANNER_E2E_SITE_HELPER:?set IPSCANNER_E2E_SITE_HELPER}"
IPSCANNER_API_URL=${IPSCANNER_API_URL:-http://localhost:3050}
CADDY_VERSION=${CADDY_VERSION:-v2.11.7}
BUILDER_IMAGE=${BUILDER_IMAGE:-caddy:2.11-builder}
core=${IPSCANNER_EDGE_GO_DIR:-$root/../ipscanner-edge-go}

mkdir -p "$here/.build"
set -- --with "github.com/ipscanner/ipscanner-caddy=/src/ipscanner-caddy"
mounts="-v $root:/src/ipscanner-caddy:ro"
if [ -d "$core" ]; then
	core=$(cd "$core" && pwd)
	set -- "$@" --replace "github.com/ipscanner/ipscanner-edge-go=/src/ipscanner-edge-go"
	mounts="$mounts -v $core:/src/ipscanner-edge-go:ro"
fi
echo "building caddy $CADDY_VERSION with the module"
# shellcheck disable=SC2086
docker run --rm $mounts \
	-v ipscanner-caddy-e2e-gomod:/go/pkg/mod \
	-v "$here/.build":/out \
	"$BUILDER_IMAGE" \
	xcaddy build "$CADDY_VERSION" "$@" --output /out/caddy

cleanup() {
	if [ "${KEEP:-}" != 1 ]; then
		docker compose -f "$here/docker-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT INT TERM

IPSCANNER_API_KEY=$(tr -d '[:space:]' <"$IPSCANNER_KEY_FILE")
export IPSCANNER_API_KEY
docker compose -f "$here/docker-compose.yml" up -d --force-recreate
docker run --rm -v "$here/.build":/b:ro caddy:2.11-alpine /b/caddy list-modules --versions 2>/dev/null | grep ipscanner

for _ in $(seq 1 30); do
	if curl -s -o /dev/null http://127.0.0.1:18093/; then break; fi
	sleep 1
done

export IPSCANNER_KEY_FILE IPSCANNER_E2E_SITE_HELPER IPSCANNER_API_URL
unset IPSCANNER_API_KEY
cd "$root"
go test -tags e2e -count=1 -v ./test/e2e
