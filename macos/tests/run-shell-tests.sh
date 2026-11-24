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

swiftc -module-cache-path "$scratch/module-cache" \
  "$macos/uninstall/Uninstall.swift" "$macos/tests/test_uninstall.swift" -o "$scratch/uninstall-tests"
"$scratch/uninstall-tests"
# Compile the actual macOS/Security entry point, but never run it against the host.
swiftc -target "$(uname -m)-apple-macosx13.0" -module-cache-path "$scratch/module-cache" \
  "$macos/uninstall/Uninstall.swift" "$macos/uninstall/main.swift" -o "$scratch/LoonInspect-Uninstall"
"$scratch/LoonInspect-Uninstall" --help
