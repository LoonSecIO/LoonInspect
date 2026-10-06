#!/usr/bin/env bash
# Downloads the two runtimes LoonInspect.app embeds into macos/build/downloads, pinned by
# version and sha256. Run by build-app.sh; safe to run on its own.
#
# A file already downloaded is re-hashed on every run, and any mismatch, fresh or cached,
# stops the script: the bundle never carries an artifact that is not the one pinned here.
# Moving a pin means changing a version and its sha256 together, both read from the
# upstream named beside it — never from a mirror, and never from the file just downloaded.
set -euo pipefail

macos=$(cd "$(dirname "$0")/.." && pwd)
downloads="$macos/build/downloads"
mkdir -p "$downloads"

# CPython for aarch64-apple-darwin, relocatable, from astral-sh/python-build-standalone.
# 3.12 because the image runs python:3.12-slim (backend/.python-version). The sha256 is the
# release's SHA256SUMS entry for the asset, which matches GitHub's own asset digest.
PYTHON_VERSION=3.12.15
PYTHON_RELEASE=20261003
PYTHON_ASSET="cpython-${PYTHON_VERSION}+${PYTHON_RELEASE}-aarch64-apple-darwin-install_only.tar.gz"
PYTHON_URL="https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_RELEASE}/cpython-${PYTHON_VERSION}%2B${PYTHON_RELEASE}-aarch64-apple-darwin-install_only.tar.gz"
PYTHON_SHA256=316a463172740e71d8dca1f2730784e325f3f720941137b5d674d5801a632213

# PostgreSQL 17 server binaries for darwin, from zonky's embedded-postgres-binaries on Maven
# Central: a jar wrapping a .txz of EnterpriseDB's signed, @rpath-relocatable build. 17 because
# the image's database is postgres:17-alpine. The sha256 is Maven Central's published .sha256.
POSTGRES_VERSION=17.11.0
POSTGRES_ASSET="embedded-postgres-binaries-darwin-arm64v8-${POSTGRES_VERSION}.jar"
POSTGRES_URL="https://repo1.maven.org/maven2/io/zonky/test/postgres/embedded-postgres-binaries-darwin-arm64v8/${POSTGRES_VERSION}/${POSTGRES_ASSET}"
POSTGRES_SHA256=a1c2786acb0c398f9b2d76806fc52f5dc8b222cbc8e9383a9b9702084daaf3a5

sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }

fetch() {
  local name=$1 url=$2 want=$3 got
  if [ -f "$downloads/$name" ]; then
    got=$(sha256_of "$downloads/$name")
    if [ "$got" = "$want" ]; then
      echo "fetch-runtime: $name is cached and matches its pin"
      return
    fi
    echo "fetch-runtime: cached $name has sha256 $got, but the pin is $want. Nothing was changed." >&2
    echo "fetch-runtime: remove $downloads/$name to download it again." >&2
    exit 1
  fi
  echo "fetch-runtime: downloading $name"
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --retry 3 \
    --output "$downloads/$name.part" "$url"
  got=$(sha256_of "$downloads/$name.part")
  if [ "$got" != "$want" ]; then
    rm -f "$downloads/$name.part"
    echo "fetch-runtime: $name from $url has sha256 $got, but the pin is $want. Nothing was kept." >&2
    echo "fetch-runtime: if upstream republished the file, re-read the pin from the upstream named in this script." >&2
    exit 1
  fi
  mv "$downloads/$name.part" "$downloads/$name"
  echo "fetch-runtime: $name verified ($want)"
}

fetch "$PYTHON_ASSET" "$PYTHON_URL" "$PYTHON_SHA256"
fetch "$POSTGRES_ASSET" "$POSTGRES_URL" "$POSTGRES_SHA256"

# What build-app.sh reads back, so the versions live in one place.
cat >"$downloads/runtime.env" <<PINS
PYTHON_VERSION=$PYTHON_VERSION
PYTHON_RELEASE=$PYTHON_RELEASE
PYTHON_ASSET=$PYTHON_ASSET
PYTHON_SHA256=$PYTHON_SHA256
POSTGRES_VERSION=$POSTGRES_VERSION
POSTGRES_ASSET=$POSTGRES_ASSET
POSTGRES_SHA256=$POSTGRES_SHA256
PINS
