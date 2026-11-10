#!/usr/bin/env bash
# Puts macos/build/LoonInspect.app on a disk image, LoonInspect-<version>-arm64.dmg beside it, with
# an Applications link, and signs the image with the same identity as the app. Run by
# build-app.sh after the bundle is signed, and again by notarize.sh once the app is stapled, so the
# image always carries the app as it is now.
set -euo pipefail

macos=$(cd "$(dirname "$0")/.." && pwd)
build="$macos/build"
app="$build/LoonInspect.app"
die() { echo "package-dmg: $*" >&2; exit 1; }

[ -d "$app" ] || die "no $app; run macos/scripts/build-app.sh first"
version=$(plutil -extract CFBundleShortVersionString raw -o - "$app/Contents/Info.plist")
identity=$("$macos/scripts/sign-identity.sh")
dmg="$build/LoonInspect-$version-arm64.dmg"
stage="$build/dmg-stage"

rm -rf "$stage" "$dmg"
mkdir -p "$stage"
# ditto, not cp: it keeps the bundle's extended attributes, and with them the signature's seal.
ditto "$app" "$stage/LoonInspect.app"
ln -s /Applications "$stage/Applications"
hdiutil create -quiet -volname "LoonInspect $version" -srcfolder "$stage" -fs HFS+ -format UDZO -imagekey zlib-level=9 -ov "$dmg"
rm -rf "$stage"
if [ "$identity" != - ]; then
  codesign --force --sign "$identity" --timestamp "$dmg"
  codesign --verify --strict "$dmg"
else
  echo "package-dmg: the app is signed ad-hoc, so the image is not signed; it runs here and nowhere else" >&2
fi
du -sh "$dmg"
