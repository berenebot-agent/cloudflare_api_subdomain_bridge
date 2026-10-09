#!/bin/bash
# cloudflare-go.sh — run Go commands inside Docker (build/test/vet/tidy) with a
# persistent cache so repeated runs are fast, and libsqlite3-dev pre-baked so
# every run doesn't pay apt-get (store.go is cgo, linked against libsqlite3).
#
# Go is intentionally NOT installed on the host. Use this wrapper for ALL Go
# commands (build, test, vet, mod tidy). Mirrors mailmoose-go.sh / tiller-go.sh.
#
# Usage:
#   ./cloudflare-go.sh test ./...
#   ./cloudflare-go.sh vet ./...
#   ./cloudflare-go.sh build -o bridge .
#   ./cloudflare-go.sh gofmt -l .            (direct gofmt binary; fmt gate)
#
# Caches (bind-mounted, NOT named volumes):
#   gomod   = ~/.cache/cloudflare-go/mod      module download cache (/go/pkg/mod)
#   gobuild = ~/.cache/cloudflare-go/build    compiled package cache (/root/.cache/go-build)
#
# Toolchain image:
#   Base pinned to match the Dockerfile build stage (golang:1.26-bookworm). The
#   wrapper builds a local cached image (cloudflare-go:1.26) with libsqlite3-dev
#   preinstalled on first use, then reuses it. Override with CLOUDFLARE_GO_IMAGE.
#
# RAM safety:
#   --memory/-m limits the container's hard memory ceiling (OOM inside, not host
#   OOM); --memory-swap = same value => no swap growth. GOFLAGS=-p=2 cuts peak
#   compiler RAM further.

set -eu

GO_BASE="golang:1.26-bookworm"
GO_IMAGE="${CLOUDFLARE_GO_IMAGE:-cloudflare-go:1.26}"
CACHE_DIR="${CLOUDFLARE_GO_CACHE:-$HOME/.cache/cloudflare-go}"
MOD_CACHE="$CACHE_DIR/mod"
BUILD_CACHE="$CACHE_DIR/build"
MEM_LIMIT="${CLOUDFLARE_GO_MEM:-2g}"   # hard RAM cap for the container

mkdir -p "$MOD_CACHE" "$BUILD_CACHE"

# Repo root = this script's own directory (the dir containing go.mod).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT="$SCRIPT_DIR"

# Build the cached toolchain image once (libsqlite3-dev pre-baked for cgo).
if ! docker image inspect "$GO_IMAGE" >/dev/null 2>&1; then
    echo "cloudflare-go.sh: building cached image $GO_IMAGE ..." >&2
    docker build -f "$REPO_ROOT/tests/docker/Dockerfile.gocache" \
        --build-arg "GO_BASE=$GO_BASE" \
        -t "$GO_IMAGE" "$REPO_ROOT/tests/docker" >&2
fi

# A container without a TTY/terminal shouldn't try to allocate one.
TTY_FLAG=""
if [ -t 1 ]; then TTY_FLAG="-it"; fi

ENV_FLAGS="-e GOFLAGS=-p=2 -e CGO_ENABLED=1"

# gofmt passthrough: `go fmt` is not `gofmt -l`, and the CI check wants the
# latter, so run the gofmt binary directly when asked.
if [ "${1:-}" = "gofmt" ]; then
    echo "==> cloudflare-go.sh: gofmt ${*:2}" >&2
    exec docker run $TTY_FLAG --rm \
        --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" \
        $ENV_FLAGS \
        -v "$MOD_CACHE:/go/pkg/mod" \
        -v "$BUILD_CACHE:/root/.cache/go-build" \
        -v "$REPO_ROOT:/src" -w /src \
        "$GO_IMAGE" \
        gofmt "${@:2}"
fi

echo "==> cloudflare-go.sh: go $*" >&2
exec docker run $TTY_FLAG --rm \
    --memory="$MEM_LIMIT" --memory-swap="$MEM_LIMIT" \
    $ENV_FLAGS \
    -v "$MOD_CACHE:/go/pkg/mod" \
    -v "$BUILD_CACHE:/root/.cache/go-build" \
    -v "$REPO_ROOT:/src" -w /src \
    "$GO_IMAGE" \
    go "$@"
