#!/usr/bin/env bash
# Builds macos/build/LoonInspect.app: the backend, the built frontend, a relocatable CPython 3.12
# and PostgreSQL 17 under a small Swift shell, signed ad-hoc (unsigned for distribution).
#
# Contents/Resources/backend is laid out the way the image lays out /app: app/ with the SPA in
# app/static and build_info.json, migrations/, alembic.ini, docs/baseline-rules.yml. The backend's
# locked runtime dependencies are exported from uv.lock by uv in Docker and installed on this
# host, by the bundled Python, as macOS arm64 wheels checked against the lockfile's hashes.
# Postgres goes to Contents/Resources/postgres. Needs Xcode's swift, node and npm (the image and
# CI use node 22), Docker (only for `uv export`), and the network for the pinned downloads.
#
#   macos/scripts/build-app.sh          # then: open macos/build/LoonInspect.app
set -euo pipefail

started=$(date +%s)
macos=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$macos/.." && pwd)
build="$macos/build"
app="$build/LoonInspect.app"
res="$app/Contents/Resources"
src="$build/src"
# The Dockerfile's and CI's uv (0.9.30), pinned by the registry's index digest as well, so a
# re-pushed tag cannot change what runs. `uv export` output is platform-neutral (markers and
# every wheel's hash), so the image's OS does not matter here.
UV_IMAGE=${UV_IMAGE:-ghcr.io/astral-sh/uv:0.9.30-python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58}

step() { printf '\n== %s  [%ss]\n' "$*" "$(($(date +%s) - started))"; }
die() { echo "build-app: $*" >&2; exit 1; }
# Universal Mach-O files keep only their arm64 slice. lipo copies that slice, its own signature
# included, so a file signed upstream (EnterpriseDB's Developer ID, a linker's ad-hoc) still
# verifies; the x86_64 slice of a universal2 wheel is often not signed at all.
thin_to_arm64() {
  find "$@" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) | while read -r f; do
    if lipo -archs "$f" 2>/dev/null | grep -q x86_64; then lipo "$f" -thin arm64 -output "$f.arm64" && mv "$f.arm64" "$f"; fi
  done
}

[ "$(uname -m)" = arm64 ] || die "this spike builds for Apple silicon only, and uname -m says $(uname -m)"
for tool in swift node npm docker codesign lipo shasum git; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done

step "runtimes: pinned by version and sha256"
"$macos/scripts/fetch-runtime.sh"
# shellcheck source=/dev/null
. "$build/downloads/runtime.env"

step "source: what the image copies, from this working tree"
rm -rf "$app" "$src" "$build/requirements.txt"
mkdir -p "$src/backend/docs" "$res" "$app/Contents/MacOS"
# An allowlist rather than the tree, so a local backend/.env never rides along (INSPECT-0175).
(cd "$repo/backend" && tar -cf - --exclude __pycache__ --exclude '*.pyc' app migrations alembic.ini pyproject.toml uv.lock) |
  tar -xf - -C "$src/backend"
rm -rf "$src/backend/app/static" "$src/backend/app/build_info.json"
cp "$repo/docs/baseline-rules.yml" "$src/backend/docs/"
# .env files excluded as .dockerignore excludes them: Vite would read one into the build.
(cd "$repo" && tar -cf - --exclude node_modules --exclude dist --exclude '*.tsbuildinfo' --exclude .env --exclude '.env.*' frontend) |
  tar -xf - -C "$src"

step "frontend: npm ci && npm run build, node $(node --version)"
[ "$(node -p 'process.versions.node.split(".")[0]')" = 22 ] ||
  echo "build-app: note: node $(node --version) here; the image and CI build the frontend with node 22" >&2
(cd "$src/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build >"$build/frontend-build.log" 2>&1) ||
  die "the frontend build failed; its output is in $build/frontend-build.log"

step "python: CPython $PYTHON_VERSION ($PYTHON_RELEASE), then the locked runtime dependencies"
tar -xzf "$build/downloads/$PYTHON_ASSET" -C "$res"
py="$res/python/bin/python3"
docker run --rm --network none -v "$src/backend:/src:ro" -w /src "$UV_IMAGE" \
  uv export --frozen --no-dev --no-emit-project --format requirements-txt >"$build/requirements.txt"
# --isolated: no pip.conf or PIP_* variable of this machine's (an index URL, say) applies.
"$py" -m pip install --isolated --quiet --cache-dir "$build/cache/pip" \
  --disable-pip-version-check --no-warn-script-location --no-compile \
  --require-hashes --no-deps --only-binary=:all: -r "$build/requirements.txt"
"$py" -m pip uninstall --isolated --quiet --disable-pip-version-check --yes pip
# What the backend never runs: Tk and IDLE, headers, the embedding library (bin/python3.12 is
# static), pip's bundled wheel, and console scripts whose shebangs name this build directory.
(cd "$res/python" && rm -rf include share lib/pkgconfig lib/libpython3.12.dylib lib/itcl* lib/tcl* lib/tk* lib/thread* lib/libtcl* \
  lib/python3.12/idlelib lib/python3.12/tkinter lib/python3.12/turtledemo lib/python3.12/ensurepip lib/python3.12/lib2to3 \
  lib/python3.12/lib-dynload/_tkinter*)
find "$res/python/bin" -mindepth 1 ! -name python ! -name python3 ! -name python3.12 -delete
thin_to_arm64 "$res/python"

step "backend: laid out as the image's /app"
mkdir -p "$res/backend" "$res/launcher"
cp -R "$src/backend/app" "$src/backend/migrations" "$src/backend/alembic.ini" "$src/backend/docs" "$res/backend/"
cp -R "$src/frontend/dist" "$res/backend/app/static"
commit=$(git -C "$repo" rev-parse HEAD)
printf '{"version": "%s+%s"}\n' "$(date -u +%Y.%m.%d)" "${commit:0:7}" >"$res/backend/app/build_info.json"
cp "$macos/launcher/loon_backend.py" "$res/launcher/"

step "bytecode: compiled now, unchecked-hash, so nothing writes into the signed bundle at run time"
"$py" -m compileall -q -j 0 --invalidation-mode unchecked-hash "$res/python/lib/python3.12" "$res/backend" "$res/launcher" >/dev/null

step "postgres: zonky $POSTGRES_VERSION, arm64 slices only, duplicate libraries linked"
mkdir -p "$res/postgres" "$build/postgres-jar"
unzip -q -o "$build/downloads/$POSTGRES_ASSET" postgres-darwin-arm_64.txz -d "$build/postgres-jar"
tar -xJf "$build/postgres-jar/postgres-darwin-arm_64.txz" -C "$res/postgres"
rm -rf "$build/postgres-jar"
thin_to_arm64 "$res/postgres/bin" "$res/postgres/lib"
# The jar carries each library under every name it answers to, as separate copies.
(cd "$res/postgres/lib" && shasum -a 256 -- *.dylib | sort |
  awk '{ if ($1 == hash) print keep, $2; else { hash = $1; keep = $2 } }' |
  while read -r keep copy; do ln -sf "$keep" "$copy"; done)

step "shell: swift build -c release"
swift build -c release --package-path "$macos/shell" --scratch-path "$build/swift"
bin=$(swift build -c release --package-path "$macos/shell" --scratch-path "$build/swift" --show-bin-path)
[ -x "$bin/LoonInspect" ] || die "swift build produced no $bin/LoonInspect"
cp "$bin/LoonInspect" "$app/Contents/MacOS/LoonInspect"
cp "$macos/shell/Info.plist" "$app/Contents/Info.plist"
release=$(sed -n 's/^RELEASE = "v\(.*\)"$/\1/p' "$repo/backend/app/core/version.py")
plutil -replace CFBundleShortVersionString -string "${release:-0.0.0}" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$(date -u +%Y%m%d.%H%M)" "$app/Contents/Info.plist"
printf 'APPL????' >"$app/Contents/PkgInfo"
cat >"$res/build-manifest.json" <<JSON
{
  "built": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "commit": "$commit",
  "python": "$PYTHON_VERSION+$PYTHON_RELEASE ($PYTHON_SHA256)",
  "postgres": "zonky $POSTGRES_VERSION ($POSTGRES_SHA256)",
  "requirements": "$(shasum -a 256 "$build/requirements.txt" | cut -d' ' -f1)",
  "node": "$(node --version)"
}
JSON

step "sign: ad-hoc, and check every Mach-O in the bundle still verifies"
xattr -cr "$app" 2>/dev/null || true
codesign --force --sign - --timestamp=none "$app"
codesign --verify --strict --deep "$app"
unsigned=0
while read -r f; do
  codesign --verify --strict "$f" 2>/dev/null || { echo "build-app: signature does not verify: $f" >&2; unsigned=$((unsigned + 1)); }
done < <(find "$res" -type f \( -name '*.so' -o -name '*.dylib' -o -path '*/bin/*' \) ! -name '*.py' -exec sh -c 'file -b "$1" | grep -q Mach-O' _ {} \; -print)
[ "$unsigned" = 0 ] || die "$unsigned Mach-O file(s) in the bundle do not verify"

step "size"
du -sh "$app" "$res/python" "$res/postgres" "$res/backend" "$app/Contents/MacOS"
ditto -c -k --keepParent "$app" "$build/LoonInspect.zip"
du -sh "$build/LoonInspect.zip"
echo "build-app: done in $(($(date +%s) - started)) s: $app"
