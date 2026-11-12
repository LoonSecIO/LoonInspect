#!/usr/bin/env python3
"""Exercise the real notarization script with an isolated bundle and fake Apple tools.

Run with LOONINSPECT_NOTARIZE_SCRIPT=/path/to/macos/scripts/notarize.sh python3
test_notarize.py. When installed in the repository, the script is found in an ancestor.
No signing key, Apple account, network, or real notarization service is used.
"""

import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

IDENTITY = "Developer ID Application: Test Publisher (TESTTEAM01)"
TEAM = "TESTTEAM01"
APP_ID = "11111111-1111-4111-8111-111111111111"
DMG_ID = "22222222-2222-4222-8222-222222222222"


def script_path():
    configured = os.environ.get("LOONINSPECT_NOTARIZE_SCRIPT")
    if configured:
        return Path(configured).resolve()
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "macos/scripts/notarize.sh"
        if candidate.is_file():
            return candidate
    raise RuntimeError("Set LOONINSPECT_NOTARIZE_SCRIPT to macos/scripts/notarize.sh")


FAKE_TOOL = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
trace = Path(os.environ["TEST_TRACE"])
scenario = os.environ["TEST_SCENARIO"]
app_id = "11111111-1111-4111-8111-111111111111"
dmg_id = "22222222-2222-4222-8222-222222222222"

def record(operation, **extra):
    with trace.open("a") as out:
        out.write(json.dumps({"operation": operation, "args": args, **extra}) + "\n")

def answer(value, status=0):
    print(json.dumps(value))
    sys.exit(status)

def fail(message):
    print(message, file=sys.stderr)
    sys.exit(91)

if name == "security":
    record("security")
    if args[:1] != ["find-identity"]:
        fail("Unexpected security command in test")
    print('  1) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: Test Publisher (TESTTEAM01)"')
    print("     1 valid identities found")
elif name == "codesign":
    record("codesign")
    if any(arg.startswith("-d") for arg in args) or "--display" in args:
        print("Identifier=io.loonsec.looninspect", file=sys.stderr)
        print("Authority=Developer ID Application: Test Publisher (TESTTEAM01)", file=sys.stderr)
        print("TeamIdentifier=TESTTEAM01", file=sys.stderr)
        print("Timestamp=Nov 12, 2026 at 12:00:00 PM", file=sys.stderr)
        print("CodeDirectory v=20500 flags=0x10000(runtime)", file=sys.stderr)
elif name == "ditto":
    source, destination = map(Path, args[-2:])
    stapled = (source / ".test-stapled").exists()
    record("zip", stapled=stapled)
    destination.write_text(json.dumps({"app_stapled": stapled}))
elif name == "package-dmg.sh":
    build = Path(os.environ["TEST_BUILD"])
    stapled = (build / "LoonInspect.app/.test-stapled").exists()
    record("package-dmg", app_stapled=stapled)
    (build / "LoonInspect-1.0.0-arm64.dmg").write_text(json.dumps({"app_stapled": stapled}))
elif name == "spctl":
    record("assess", target=Path(args[-1]).suffix)
    print("accepted\nsource=Notarized Developer ID", file=sys.stderr)
elif name == "xcrun":
    if args[:1] == ["notarytool"]:
        action = args[1]
        record("notary-" + action)
        if action == "history":
            answer({"history": [], "message": "Successfully received submission history."})
        if action == "submit":
            payload = Path(args[2])
            kind = "app" if payload.suffix == ".zip" else "dmg"
            submission_id = app_id if kind == "app" else dmg_id
            record("submitted-" + kind, payload=json.loads(payload.read_text()))
            if "--wait" in args:
                if kind == "app" and scenario == "invalid":
                    answer({"id": submission_id, "status": "Invalid"}, 1)
                if kind == "app" and scenario == "timeout":
                    answer({"id": submission_id, "status": "In Progress"}, 69)
                answer({"id": submission_id, "status": "Accepted"})
            answer({"id": submission_id, "message": "Successfully uploaded file"})
        if action == "wait":
            submission_id = args[2]
            if submission_id == app_id and scenario == "invalid":
                answer({"id": submission_id, "status": "Invalid"}, 1)
            if submission_id == app_id and scenario == "timeout":
                print("Timeout reached while waiting for notarization.", file=sys.stderr)
                answer({"id": submission_id, "status": "In Progress"}, 69)
            answer({"id": submission_id, "status": "Accepted"})
        if action == "log":
            submission_id = args[2]
            if scenario == "timeout":
                print("Submission is still processing; log is not available.", file=sys.stderr)
                sys.exit(65)
            log = {"jobId": submission_id, "status": "Invalid", "issues": [
                {"path": "LoonInspect.app/Contents/Resources/python/bin/python3", "message": "The signature does not include a secure timestamp."}
            ]}
            # notarytool log accepts an optional output file, including after options.
            values = []
            index = 3
            while index < len(args):
                if args[index].startswith("-"):
                    index += 2
                else:
                    values.append(args[index])
                    index += 1
            if values:
                Path(values[-1]).write_text(json.dumps(log))
            else:
                print(json.dumps(log))
        elif action not in {"history", "submit", "wait"}:
            fail("Unexpected notarytool action: " + action)
    elif args[:1] == ["stapler"]:
        action = args[1]
        target = Path(args[-1])
        kind = "app" if target.suffix == ".app" else "dmg"
        marker = target / ".test-stapled" if target.is_dir() else target.with_suffix(".stapled")
        record(action + "-" + kind)
        if action == "staple":
            marker.write_text("stapled")
        elif action == "validate":
            if not marker.exists():
                fail("Validation attempted before stapling")
        else:
            fail("Unexpected stapler action: " + action)
    else:
        fail("Unexpected xcrun command")
else:
    fail("Unexpected fake tool: " + name)
"""


@unittest.skipUnless(
    sys.platform == "darwin", "Uses macOS plutil to parse the real manifest"
)
class NotarizeIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="looninspect-notarize-test-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.macos = self.root / "macos"
        self.scripts = self.macos / "scripts"
        self.build = self.macos / "build"
        self.app = self.build / "LoonInspect.app"
        self.bin = self.root / "bin"
        self.trace = self.root / "commands.jsonl"
        self.keychain = self.root / "test signing.keychain-db"
        self.keychain.touch()
        self.scripts.mkdir(parents=True)
        self.bin.mkdir()
        (self.app / "Contents/Resources").mkdir(parents=True)

        source = script_path()
        if not source.is_file():
            self.fail(f"No notarization script at {source}")
        self.script = self.scripts / "notarize.sh"
        shutil.copy2(source, self.script)
        identity_script = source.with_name("sign-identity.sh")
        if not identity_script.is_file():
            self.fail(f"No identity script at {identity_script}")
        shutil.copy2(identity_script, self.scripts / "sign-identity.sh")

        fake = self.bin / "fake-apple-tool"
        fake.write_text(FAKE_TOOL)
        fake.chmod(0o755)
        for name in ("xcrun", "codesign", "security", "ditto", "spctl"):
            (self.bin / name).symlink_to(fake)
        (self.scripts / "package-dmg.sh").symlink_to(fake)

        (self.app / "Contents/Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "io.loonsec.looninspect",
                    "CFBundleShortVersionString": "1.0.0",
                    "CFBundleVersion": "1",
                }
            )
        )
        (self.app / "Contents/Resources/build-manifest.json").write_text(
            json.dumps(
                {
                    "app": "1.0.0",
                    "backend_release": "v1.0.0",
                    "commit": "a" * 40,
                    "tree": "clean",
                    "signed_as": IDENTITY,
                }
            )
        )

    def run_script(self, scenario="accepted", with_profile=True):
        env = os.environ.copy()
        for name in (
            "NOTARY_PROFILE",
            "NOTARY_KEYCHAIN",
            "NOTARY_TIMEOUT",
            "ALLOW_DIRTY",
            "SIGN_IDENTITY",
            "EXPECTED_TEAM_ID",
        ):
            env.pop(name, None)
        env.update(
            {
                "PATH": f"{self.bin}:{env.get('PATH', '/usr/bin:/bin')}",
                "TEST_TRACE": str(self.trace),
                "TEST_BUILD": str(self.build),
                "TEST_SCENARIO": scenario,
                "SIGN_IDENTITY": IDENTITY,
                "EXPECTED_TEAM_ID": TEAM,
                "NOTARY_KEYCHAIN": str(self.keychain),
                "NOTARY_TIMEOUT": "7s",
            }
        )
        if with_profile:
            env["NOTARY_PROFILE"] = "test-notary-profile"
        return subprocess.run(
            ["/bin/bash", str(self.script)],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def calls(self):
        if not self.trace.exists():
            return []
        return [json.loads(line) for line in self.trace.read_text().splitlines()]

    def assert_keychain_arguments(self):
        notary_calls = [
            call for call in self.calls() if call["operation"].startswith("notary-")
        ]
        self.assertTrue(notary_calls, "No notarytool calls were made")
        for call in notary_calls:
            with self.subTest(operation=call["operation"]):
                args = call["args"]
                self.assertIn("--keychain-profile", args)
                self.assertEqual(
                    args[args.index("--keychain-profile") + 1], "test-notary-profile"
                )
                self.assertIn("--keychain", args)
                self.assertEqual(args[args.index("--keychain") + 1], str(self.keychain))

    def assert_failed_before_stapling(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        operations = [call["operation"] for call in self.calls()]
        self.assertFalse(any(op.startswith("staple-") for op in operations))
        self.assertNotIn("package-dmg", operations)
        self.assertNotIn("submitted-dmg", operations)
        self.assertNotIn("assess", operations)

    def test_accepted_app_then_dmg_are_stapled_and_verified(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        operations = [call["operation"] for call in calls]
        expected = [
            "submitted-app",
            "staple-app",
            "package-dmg",
            "submitted-dmg",
            "staple-dmg",
            "validate-app",
            "validate-dmg",
        ]
        positions = [operations.index(operation) for operation in expected]
        self.assertEqual(positions, sorted(positions), operations)
        self.assertEqual(sum(op == "submitted-app" for op in operations), 1)
        self.assertEqual(sum(op == "submitted-dmg" for op in operations), 1)
        self.assertEqual(
            {call["target"] for call in calls if call["operation"] == "assess"},
            {".app", ".dmg"},
        )
        zipped = [call["stapled"] for call in calls if call["operation"] == "zip"]
        self.assertEqual(
            zipped, [False, True], "Release ZIP must be recreated after app stapling"
        )
        packaged = next(call for call in calls if call["operation"] == "package-dmg")
        self.assertTrue(packaged["app_stapled"], "DMG must contain the stapled app")
        final_zip = json.loads((self.build / "LoonInspect-1.0.0-arm64.zip").read_text())
        self.assertTrue(final_zip["app_stapled"])
        for kind, expected_id in (("app", APP_ID), ("dmg", DMG_ID)):
            submitted = json.loads((self.build / f"notarize-{kind}.json").read_text())
            self.assertEqual(submitted["id"], expected_id)
            status = json.loads(
                (self.build / f"notarize-{kind}-status.json").read_text()
            )
            self.assertEqual(status["status"], "Accepted")
        checksum_lines = (self.build / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksum_lines), 2)
        for line in checksum_lines:
            digest, name = line.split(maxsplit=1)
            self.assertEqual(
                digest, hashlib.sha256((self.build / name).read_bytes()).hexdigest()
            )
        timed_calls = [
            call
            for call in calls
            if call["operation"] == "notary-wait"
            or (call["operation"] == "notary-submit" and "--wait" in call["args"])
        ]
        self.assertEqual(len(timed_calls), 2)
        for call in timed_calls:
            self.assertEqual(call["args"][call["args"].index("--timeout") + 1], "7s")
        self.assert_keychain_arguments()

    def test_invalid_nonzero_wait_still_fetches_apple_log(self):
        result = self.run_script("invalid")
        self.assert_failed_before_stapling(result)
        output = result.stdout + result.stderr
        self.assertIn(APP_ID, output)
        self.assertIn("Invalid", output)
        log_path = self.build / "notarize-app.log"
        self.assertTrue(log_path.is_file(), output)
        log = json.loads(log_path.read_text())
        self.assertEqual(log["jobId"], APP_ID)
        self.assertTrue(log["issues"])
        self.assertIn("notary-log", [call["operation"] for call in self.calls()])
        self.assert_keychain_arguments()

    def test_timeout_retains_submission_id_and_recovery_command(self):
        result = self.run_script("timeout")
        self.assert_failed_before_stapling(result)
        output = result.stdout + result.stderr
        submitted = json.loads((self.build / "notarize-app.json").read_text())
        self.assertEqual(submitted["id"], APP_ID)
        self.assertIn(APP_ID, output)
        self.assertRegex(output, r"(?i)(time.?out|in progress|still processing)")
        self.assertIn(
            "notarytool",
            output,
            "Timeout must explain how to inspect or resume this submission",
        )
        status_path = self.build / "notarize-app-status.json"
        self.assertTrue(status_path.exists(), output)
        status = json.loads(status_path.read_text())
        self.assertEqual(status["id"], APP_ID)
        self.assertEqual(status["status"], "In Progress")
        self.assert_keychain_arguments()

    def test_missing_profile_refuses_before_contacting_apple(self):
        result = self.run_script(with_profile=False)
        self.assert_failed_before_stapling(result)
        self.assertIn("NOTARY_PROFILE", result.stdout + result.stderr)
        self.assertFalse(
            any(call["operation"].startswith("notary-") for call in self.calls())
        )
        self.assertFalse((self.build / "notarize-app.json").exists())
        self.assertFalse((self.build / "LoonInspect-1.0.0-arm64.zip").exists())


if __name__ == "__main__":
    unittest.main()
