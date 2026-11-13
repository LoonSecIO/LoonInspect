#!/usr/bin/env bash
# Native shell checks use disposable files and processes, never this Mac's LoonInspect data.
set -euo pipefail
macos=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/looninspect-native-tests.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
python3 "$macos/tests/test_shell_reliability.py"
swiftc -module-cache-path "$scratch/module-cache" \
  "$macos/shell/Sources/LoonInspect/ExportDestination.swift" \
  "$macos/tests/test_exports.swift" -o "$scratch/exports"
"$scratch/exports"
