"""Check shell recovery helpers without launching the app or accessing the Keychain.

Run with python3 macos/tests/test_shell_reliability.py. Swift checks require macOS and
Xcode's compiler. They compile the real shell sources into an isolated test executable;
all files live in a temporary directory, and Supervisor is never instantiated.
"""

import importlib.util
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

MACOS = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "loon_backend", MACOS / "launcher/loon_backend.py"
)
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)

SWIFT_HARNESS = r"""
import Foundation

signal(SIGPIPE, SIG_IGN)
switch CommandLine.arguments[1] {
case "port":
    for value in CommandLine.arguments.dropFirst(2) {
        var requests: [Int] = []
        let chosen = Supervisor.selectPort(remembered: value) { requested in
            // This has the real binder's narrowing conversion, without opening any sockets.
            _ = UInt16(requested)
            requests.append(requested)
            return requested == 0 ? 60000 : requested
        }
        print("\(chosen):\(requests.map(String.init).joined(separator: ","))")
    }
case "port-busy":
    var requests: [Int] = []
    let chosen = try Supervisor.selectPort(remembered: "49152") { requested in
        requests.append(requested)
        if requested != 0 { throw ShellFailure("The saved port is occupied") }
        return 60000
    }
    print("\(chosen):\(requests.map(String.init).joined(separator: ","))")
case "log":
    let log = ShellLog(url: URL(fileURLWithPath: CommandLine.arguments[2]))
    log.info("survived a failed log sink")
    print("survived")
case "closed-input":
    do {
        _ = try runTool("/usr/bin/true", [], stdin: String(repeating: "x", count: 1_048_576))
        fatalError("Expected the tool to close its input")
    } catch {
        print("reported closed input")
    }
default:
    fatalError("Unknown harness operation")
}
"""


@unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("swiftc"), "requires macOS and swiftc"
)
class ShellReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="looninspect-shell-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        harness = cls.root / "main.swift"
        harness.write_text(SWIFT_HARNESS)
        cls.executable = cls.root / "shell-check"
        sources = MACOS / "shell/Sources/LoonInspect"
        result = subprocess.run(
            [
                "swiftc",
                "-module-cache-path",
                str(cls.root / "module-cache"),
                str(sources / "Tools.swift"),
                str(sources / "Supervisor.swift"),
                str(harness),
                "-o",
                str(cls.executable),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode:
            raise RuntimeError(f"Swift test harness did not compile:\n{result.stderr}")

    def test_remembered_ports_reject_invalid_values_before_integer_conversion(self):
        values = [
            "-1",
            "0",
            "65536",
            "999999999999999999999999",
            "broken",
            "",
            " 49152\n",
            "1",
            "65535",
        ]
        result = subprocess.run(
            [str(self.executable), "port", *values],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            ["60000:0"] * 6 + ["49152:49152", "1:1", "65535:65535"],
        )

    def test_occupied_saved_port_falls_back_to_a_new_port(self):
        result = subprocess.run(
            [str(self.executable), "port-busy"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "60000:49152,0")

    def test_closed_stderr_does_not_prevent_file_logging(self):
        target = self.root / "broken-stderr.log"
        reader, writer = os.pipe()
        os.close(reader)
        try:
            result = subprocess.run(
                [str(self.executable), "log", str(target)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=writer,
                text=True,
                timeout=10,
            )
        finally:
            os.close(writer)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "survived")
        self.assertIn("INFO survived a failed log sink", target.read_text())

    def test_file_write_error_does_not_prevent_stderr_logging(self):
        # Restrict only this disposable child. Ignoring SIGXFSZ makes write return EFBIG,
        # exercising the same FileHandle error path as a full log volume, without filling it.
        def reject_file_writes():
            import resource

            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))

        target = self.root / "unwritable.log"
        result = subprocess.run(
            [str(self.executable), "log", str(target)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            preexec_fn=reject_file_writes,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "survived")
        self.assertIn("INFO survived a failed log sink", result.stderr)
        self.assertEqual(target.stat().st_size, 0)

    def test_tool_closed_input_reports_failure_without_crashing(self):
        result = subprocess.run(
            [str(self.executable), "closed-input"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "reported closed input")


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        LAUNCHER._shell_gone.clear()
        self.addCleanup(LAUNCHER._shell_gone.clear)

    def test_main_uses_shell_pid_even_when_already_reparented(self):
        serve = types.ModuleType("app.serve")
        serve.main = mock.Mock(return_value=0)
        with (
            mock.patch.dict(os.environ, {"LOON_SHELL_PID": "4321"}),
            mock.patch.dict(
                sys.modules, {"app": types.ModuleType("app"), "app.serve": serve}
            ),
            mock.patch.object(LAUNCHER.os, "getppid", return_value=1),
            mock.patch.object(LAUNCHER.signal, "signal"),
            mock.patch.object(LAUNCHER.threading, "Thread") as thread,
        ):
            self.assertEqual(LAUNCHER.main(), 0)
        self.assertEqual(thread.call_args.kwargs["args"], (4321,))
        thread.return_value.start.assert_called_once_with()
        serve.main.assert_called_once_with()

    def test_watchdog_stops_children_when_parent_was_already_lost(self):
        self.check_watchdog([1], [LAUNCHER.GRACE_SECONDS])

    def test_watchdog_still_waits_while_expected_shell_is_alive(self):
        self.check_watchdog([4321, 4321, 1], [1, 1, LAUNCHER.GRACE_SECONDS])

    def check_watchdog(self, parents, sleeps):
        # Every signal/exit is mocked; this test never signals a real process or sleeps.
        with (
            mock.patch.object(LAUNCHER.os, "getppid", side_effect=parents),
            mock.patch.object(LAUNCHER.os, "getpid", return_value=5678),
            mock.patch.object(LAUNCHER.os, "kill") as kill,
            mock.patch.object(LAUNCHER.time, "sleep") as sleep,
            mock.patch.object(LAUNCHER, "_stop_postgres") as stop,
            mock.patch.object(LAUNCHER.os, "_exit") as exit_process,
        ):
            LAUNCHER._watch(4321)
        self.assertTrue(LAUNCHER._shell_gone.is_set())
        kill.assert_called_once_with(5678, signal.SIGTERM)
        self.assertEqual(sleep.call_args_list, [mock.call(value) for value in sleeps])
        stop.assert_called_once_with()
        exit_process.assert_called_once_with(1)

    def test_postgres_cleanup_never_signals_a_newer_database_process(self):
        with tempfile.TemporaryDirectory(
            prefix="looninspect-watchdog-tests-"
        ) as directory:
            (Path(directory) / "postmaster.pid").write_text("8765\n")
            with (
                mock.patch.dict(
                    os.environ,
                    {"LOON_SHELL_PGDATA": directory, "LOON_SHELL_POSTGRES_PID": "4321"},
                ),
                mock.patch.object(LAUNCHER.os, "kill") as kill,
            ):
                LAUNCHER._stop_postgres()
            kill.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
