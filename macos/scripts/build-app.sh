#!/usr/bin/env bash
# Builds macos/build/LoonInspect.app and its disk image: the backend, the built frontend, a
# relocatable CPython 3.12 and PostgreSQL 17 under a small Swift shell, every Mach-O file signed
# with the hardened runtime. With a "Developer ID Application" identity in the keychain the build
# is the one a release ships, once macos/scripts/notarize.sh has had Apple notarize it; without
# one it is signed ad-hoc, which runs on this Mac and is refused by Gatekeeper on any other.
#
# Contents/Resources/backend is laid out the way the image lays out /app: app/ with the SPA in
# app/static and build_info.json, migrations/, alembic.ini, docs/baseline-rules.yml. The backend's
# locked runtime dependencies are exported from uv.lock by pinned native uv and installed on this
# host, by the bundled Python, as macOS arm64 wheels checked against the lockfile's hashes.
# Postgres goes to Contents/Resources/postgres. Needs Xcode's swift, node and npm (the image and
# CI use node 22), uv 0.9.30, and the network for the pinned downloads and
# the signature timestamps.
#
#   macos/scripts/build-app.sh                       # then: open macos/build/LoonInspect.app
#   SIGN_IDENTITY=- macos/scripts/build-app.sh       # ad-hoc on purpose, with a Developer ID in the keychain
#   BUILD_NUMBER=42 macos/scripts/build-app.sh       # CFBundleVersion; default is the UTC build minute
set -euo pipefail

started=$(date +%s)
macos=$(cd "$(dirname "$0")/.." && pwd)
repo=$(cd "$macos/.." && pwd)
build="$macos/build"
app="$build/LoonInspect.app"
res="$app/Contents/Resources"
src="$build/src"
# Match the lockfile exporter used by the container build without needing a Docker daemon
# on hosted macOS runners. The workflow installs this exact version with setup-uv.
UV_VERSION=0.9.30

step() { printf '\n== %s  [%ss]\n' "$*" "$(($(date +%s) - started))"; }
die() { echo "build-app: $*" >&2; exit 1; }
is_mach_o() { file -b "$1" | grep Mach-O >/dev/null; }
# Universal Mach-O files keep only their arm64 slice. lipo copies that slice, its own signature
# included; the x86_64 slice of a universal2 wheel is often not signed at all.
thin_to_arm64() {
  find "$@" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) | while read -r f; do
    if lipo -archs "$f" 2>/dev/null | grep x86_64 >/dev/null; then lipo "$f" -thin arm64 -output "$f.arm64" && mv "$f.arm64" "$f"; fi
  done
}

[ "$(uname -m)" = arm64 ] || die "this builds for Apple silicon only, and uname -m says $(uname -m)"
for tool in swift swiftc node npm uv codesign lipo shasum git plutil hdiutil; do
  command -v "$tool" >/dev/null || die "$tool is not on PATH"
done
[ "$(uv --version | awk '{print $2}')" = "$UV_VERSION" ] ||
  die "uv $UV_VERSION is required to export the locked dependencies; install that version and retry (macos/README.md)."

# The signature. Every Mach-O file in the bundle is signed with the same identity and the
# hardened runtime, inside out, so library validation holds and notarization has nothing to
# refuse; the bundle is sealed last. Ad-hoc keeps the same flags, so a development build fails
# where a release build would.
identity=$("$macos/scripts/sign-identity.sh")
if [ "$identity" = - ]; then
  sign=(codesign --force --sign - --timestamp=none --options runtime)
  signed_as="ad-hoc: runs on this Mac only, not for distribution"
else
  sign=(codesign --force --sign "$identity" --timestamp --options runtime)
  signed_as="$identity"
fi
[ -z "${SIGN_KEYCHAIN:-}" ] || sign+=(--keychain "$SIGN_KEYCHAIN")
version=$(plutil -extract CFBundleShortVersionString raw -o - "$macos/shell/Info.plist")
build_number=${BUILD_NUMBER:-$(date -u +%Y%m%d.%H%M)}
commit=$(git -C "$repo" rev-parse HEAD)
tree=clean
[ -z "$(git -C "$repo" status --porcelain --untracked-files=normal)" ] || tree=modified
[ "${REQUIRE_DEVELOPER_ID:-0}" != 1 ] || [ "$identity" != - ] ||
  die "a release requires a Developer ID Application identity; import the signing certificate and retry (macos/README.md)."
[ "${REQUIRE_CLEAN_TREE:-0}" != 1 ] || [ "$tree" = clean ] ||
  die "a release requires a clean checkout, including untracked files; commit or remove build inputs and retry."
echo "build-app: LoonInspect $version ($build_number) from ${commit:0:7} ($tree tree), signing as $signed_as"

step "runtimes: pinned by version and sha256"
"$macos/scripts/fetch-runtime.sh"
# shellcheck source=/dev/null
. "$build/downloads/runtime.env"

step "source: what the image copies, from this working tree"
rm -rf "$app" "$src" "$build/requirements.txt"
mkdir -p "$src/backend/docs" "$res" "$app/Contents/MacOS"
shell_source="$macos/shell"
launcher_source="$macos/launcher"
if [ "${REQUIRE_CLEAN_TREE:-0}" = 1 ]; then
  # Release inputs come from Git, so ignored local files cannot enter the signed bundle.
  git -C "$repo" archive HEAD backend frontend docs/baseline-rules.yml macos | tar -xf - -C "$src"
  cp "$src/docs/baseline-rules.yml" "$src/backend/docs/"
  shell_source="$src/macos/shell"
  launcher_source="$src/macos/launcher"
else
# An allowlist rather than the tree, so a local backend/.env never rides along (INSPECT-0175).
(cd "$repo/backend" && tar -cf - --exclude __pycache__ --exclude '*.pyc' app migrations alembic.ini pyproject.toml uv.lock) |
  tar -xf - -C "$src/backend"
rm -rf "$src/backend/app/static" "$src/backend/app/build_info.json"
cp "$repo/docs/baseline-rules.yml" "$src/backend/docs/"
# .env files excluded as .dockerignore excludes them: Vite would read one into the build.
(cd "$repo" && tar -cf - --exclude node_modules --exclude dist --exclude '*.tsbuildinfo' --exclude .env --exclude '.env.*' frontend) |
  tar -xf - -C "$src"
fi
rm -rf "$src/backend/app/static" "$src/backend/app/build_info.json"

step "frontend: npm ci && npm run build, node $(node --version)"
[ "$(node -p 'process.versions.node.split(".")[0]')" = 22 ] ||
  echo "build-app: note: node $(node --version) here; the image and CI build the frontend with node 22" >&2
(cd "$src/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build >"$build/frontend-build.log" 2>&1) ||
  die "the frontend build failed; its output is in $build/frontend-build.log"

step "python: CPython $PYTHON_VERSION ($PYTHON_RELEASE), then the locked runtime dependencies"
tar -xzf "$build/downloads/$PYTHON_ASSET" -C "$res"
py="$res/python/bin/python3"
(cd "$src/backend" && uv export --offline --frozen --no-dev --no-emit-project --format requirements-txt) >"$build/requirements.txt"
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
# The same stamp the Dockerfile writes, so the page's build readout and the update check read it as they read an image's.
printf '{"version": "%s+%s"}\n' "$(date -u +%Y.%m.%d)" "${commit:0:7}" >"$res/backend/app/build_info.json"
cp "$launcher_source/loon_backend.py" "$res/launcher/"

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

step "icon: LoonInspect.icns from the brand mark"
swiftc -O -o "$build/make-icon" "$macos/scripts/make-icon.swift"
"$build/make-icon" "$src/frontend/public/brand/loon-mark-reversed.svg" "$res/LoonInspect.icns" "$build"

step "shell: swift build -c release"
swift build -c release --package-path "$shell_source" --scratch-path "$build/swift"
bin=$(swift build -c release --package-path "$shell_source" --scratch-path "$build/swift" --show-bin-path)
[ -x "$bin/LoonInspect" ] || die "swift build produced no $bin/LoonInspect"
cp "$bin/LoonInspect" "$app/Contents/MacOS/LoonInspect"
cp "$macos/shell/Info.plist" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$build_number" "$app/Contents/Info.plist"
printf 'APPL????' >"$app/Contents/PkgInfo"
release=$(sed -n 's/^RELEASE = "\(.*\)"$/\1/p' "$repo/backend/app/core/version.py")
cat >"$res/build-manifest.json" <<JSON
{
  "app": "$version",
  "build": "$build_number",
  "built": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "commit": "$commit",
  "tree": "$tree",
  "backend_release": "$release",
  "python": "$PYTHON_VERSION+$PYTHON_RELEASE ($PYTHON_SHA256)",
  "postgres": "zonky $POSTGRES_VERSION ($POSTGRES_SHA256)",
  "requirements": "$(shasum -a 256 "$build/requirements.txt" | cut -d' ' -f1)",
  "node": "$(node --version)",
  "signed_as": "$signed_as"
}
JSON

step "sign: every Mach-O file, then the bundle, then the check"
xattr -cr "$app" 2>/dev/null || true
# Regular files only: the duplicate Postgres libraries are symlinks to a copy signed once.
# (grep without -q throughout: under pipefail, -q's early exit would fail the pipeline on codesign's SIGPIPE.)
count=0
while IFS= read -r -d '' f; do
  is_mach_o "$f" || continue
  # Preserve Apple's diagnostic: keychain access and timestamp failures need different fixes.
  if ! signing_output=$("${sign[@]}" "$f" 2>&1); then
    printf '%s\n' "$signing_output" >&2
    die "could not sign $f; read codesign's error above and check the signing keychain and timestamp service (docs/troubleshooting.md, section 25)"
  fi
  count=$((count + 1))
done < <(find "$res" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) ! -name '*.py' -print0)
echo "build-app: signed $count Mach-O files under Contents/Resources"
"${sign[@]}" "$app"
codesign --verify --strict --deep "$app"
unsigned=0
while IFS= read -r -d '' f; do
  is_mach_o "$f" || continue
  codesign --verify --strict "$f" 2>/dev/null || { echo "build-app: signature does not verify: $f" >&2; unsigned=$((unsigned + 1)); }
  codesign -d --verbose=1 "$f" 2>&1 | grep 'flags=.*runtime' >/dev/null || { echo "build-app: no hardened runtime: $f" >&2; unsigned=$((unsigned + 1)); }
done < <(find "$res" -type f \( -name '*.so' -o -name '*.dylib' -o -path '*/bin/*' \) ! -name '*.py' -print0)
[ "$unsigned" = 0 ] || die "$unsigned Mach-O file(s) in the bundle do not verify with the hardened runtime"
codesign -dvv "$app" 2>&1 | grep -E '^(Identifier|Authority|TeamIdentifier|Timestamp|Signature)=' | head -6
# What Gatekeeper would say today. A Developer ID build reads "rejected" until notarize.sh has run.
spctl --assess --type execute --verbose=2 "$app" 2>&1 | sed 's/^/build-app: spctl: /' || true

step "disk image"
du -sh "$app" "$res/python" "$res/postgres" "$res/backend" "$app/Contents/MacOS"
"$macos/scripts/package-dmg.sh"
echo "build-app: done in $(($(date +%s) - started)) s: $app and $build/LoonInspect-$version-arm64.dmg"
if [ "$identity" = - ]; then
  echo "build-app: signed ad-hoc. For a release, put a Developer ID Application identity in the keychain, build again, and run macos/scripts/notarize.sh (macos/README.md)."
else
  echo "build-app: signed with a Developer ID; Gatekeeper accepts it on other Macs once macos/scripts/notarize.sh has run."
fi
