"""Run actual AppDelegate against fake services and a disposable loopback page."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "--source-dir", type=Path, required=True, help="LoonInspect checkout to compile"
)
parser.add_argument(
    "--report", type=Path, help="Optional nonsecret JSON validation record"
)
args = parser.parse_args()
repo = args.source_dir.resolve()
sources = repo / "macos/shell/Sources/LoonInspect"
scratch_directory = tempfile.TemporaryDirectory(prefix="looninspect-window-regression-")
scratch = Path(scratch_directory.name)
app = scratch / "WindowRegression.app"
executable = app / "Contents/MacOS/WindowRegression"
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
]
source_hashes = {
    name: hashlib.sha256((sources / name).read_bytes()).hexdigest()
    for name in production_names
}
subprocess.run(
    [
        "xcrun",
        "swiftc",
        "-parse-as-library",
        "-module-cache-path",
        str(scratch / "module-cache"),
        str(root / "Fakes.swift"),
        str(root / "Harness.swift"),
        *[str(sources / name) for name in production_names],
        "-o",
        str(executable),
    ],
    check=True,
)


class Handler(BaseHTTPRequestHandler):
    sequence = 0

    def do_GET(self):
        type(self).sequence += 1
        body = f'<!doctype html><title>Isolated LoonInspect regression</title><body data-request="{self.sequence}">Disposable local test page.</body>'.encode()
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
try:
    result = subprocess.run(
        [str(executable)],
        env=env,
        timeout=90,
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
                    "exit_code": result.returncode,
                    "source_sha256": source_hashes,
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
