"""Run actual AppDelegate against fake services and a disposable loopback page."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-dir", type=Path, help="LoonInspect checkout to compile")
parser.add_argument("--report", type=Path, help="Optional nonsecret JSON validation record")
parser.add_argument(
    "--compile-only", action="store_true",
    help="Compile the isolated harness without starting AppKit or WebKit",
)
bundle = parser.add_mutually_exclusive_group()
bundle.add_argument(
    "--build-app", type=Path,
    help="Compile and retain the isolated app at this path, without running it",
)
bundle.add_argument(
    "--prebuilt-app", type=Path,
    help="Run a previously built isolated app without Xcode or a source checkout",
)
args = parser.parse_args()
if not args.prebuilt_app and args.source_dir is None:
    parser.error("--source-dir is required when compiling")
if args.prebuilt_app and args.compile_only:
    parser.error("--compile-only cannot be combined with --prebuilt-app")

scratch_directory = tempfile.TemporaryDirectory(prefix="looninspect-window-regression-")
scratch = Path(scratch_directory.name)
app = (args.prebuilt_app or args.build_app or scratch / "WindowRegression.app").resolve()
executable = app / "Contents/MacOS/WindowRegression"
metadata_file = app / "Contents/Resources/validation-build.json"

if args.prebuilt_app:
    metadata = json.loads(metadata_file.read_text())
    actual_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
    if actual_hash != metadata["executable_sha256"]:
        parser.error("Prebuilt harness executable does not match its validation record")
else:
    sources = args.source_dir.resolve() / "macos/shell/Sources/LoonInspect"
    executable.parent.mkdir(parents=True, exist_ok=True)
    (app / "Contents/Info.plist").write_text("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.loonsec.isolated-window-regression</string>
<key>CFBundleExecutable</key><string>WindowRegression</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
<key>NSQuitAlwaysKeepsWindows</key><false/>
</dict></plist>""")
    production_names = [
        "AppDelegate.swift",
        "StatusView.swift",
        "MacGuideWindow.swift",
        "ExportDestination.swift",
        "PageFindController.swift",
        "PageFindBridge.swift",
        "WindowNavigationController.swift",
    ]
    harness_names = ["Fakes.swift", "Harness.swift", "FindHarness.swift", "NavigationHarness.swift"]
    target = f"{platform.machine()}-apple-macosx13.0"
    metadata = {
        "build_target": target,
        "source_sha256": {
            name: hashlib.sha256((sources / name).read_bytes()).hexdigest()
            for name in production_names
        },
        "harness_sha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in harness_names
        },
    }
    subprocess.run(
        [
            "xcrun", "swiftc", "-parse-as-library", "-target", target,
            "-module-cache-path", str(scratch / "module-cache"),
            *[str(root / name) for name in harness_names],
            *[str(sources / name) for name in production_names],
            "-o", str(executable),
        ],
        check=True,
    )
    metadata["executable_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
    metadata_file.parent.mkdir(parents=True, exist_ok=True)
    metadata_file.write_text(json.dumps(metadata, indent=2) + "\n")

if args.compile_only or args.build_app:
    print("PASS: isolated window harness compiled; GUI execution was not requested")
    if args.build_app:
        print(f"PREBUILT_APP={app}")
    if args.report:
        args.report.write_text(json.dumps({
            **metadata, "exit_code": 0, "mode": "compile-only",
            "isolation": "Compilation only; no AppKit/WebKit process, server, real app services or credentials used.",
        }, indent=2) + "\n")
    scratch_directory.cleanup()
    raise SystemExit(0)


class Handler(BaseHTTPRequestHandler):
    sequence = 0

    def do_GET(self):
        type(self).sequence += 1
        if self.path.startswith("/navigation/frame"):
            page = (
                '<!doctype html><html data-loon-theme="light"><body>Child frame theme</body>'
                '<script>addEventListener("load", () => { parent.childThemeLoaded = true; });</script></html>'
            )
            if "confirm=1" in self.path:
                page += "<script>parent.childConfirmResult = String(confirm('Child frame must not open a sheet'));</script>"
        else:
            fixture = "navigation-fixture.html" if self.path.startswith("/navigation/") else "find-fixture.html"
            page = (root / fixture).read_text()
        body = page.replace("__REQUEST__", str(self.sequence)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
env = os.environ.copy()
env["LOONINSPECT_TEST_PORT"] = str(server.server_port)
env["LOONINSPECT_TEST_DIR"] = str(scratch / "dummy-data")
visual_checkpoints = env.get("LOONINSPECT_TEST_VISUAL_CHECKPOINTS") == "1"
if visual_checkpoints:
    print(f"VISUAL_CHECKPOINT_DIR={env['LOONINSPECT_TEST_DIR']}", flush=True)
try:
    result = subprocess.run(
        [str(executable)],
        env=env,
        timeout=210 if visual_checkpoints else 90,
        capture_output=True,
        text=True,
        check=False,
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    if args.report:
        args.report.write_text(
            json.dumps(
                {
                    **metadata,
                    "exit_code": result.returncode,
                    "fixture_sha256": {
                        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                        for name in ["find-fixture.html", "navigation-fixture.html"]
                    },
                    "results": result.stdout.splitlines(),
                    "isolation": "Fake Supervisor/ShellLog, disposable loopback server, nonpersistent WebKit, frame autosaving disabled; no real app services or credentials used.",
                },
                indent=2,
            )
            + "\n"
        )
finally:
    server.shutdown()
    server.server_close()
    scratch_directory.cleanup()
raise SystemExit(result.returncode)
