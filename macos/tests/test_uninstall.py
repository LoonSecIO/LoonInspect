"""Exercise destructive uninstall only against temporary files and fake macOS services."""

import os
import plistlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

source = (
    Path(__file__).resolve().parents[1] / "scripts/Uninstall-LoonInspect.command"
).read_text()


def run_case(
    name,
    *,
    mode="ok",
    answer="ERASE LOONINSPECT\n",
    dry=False,
    symlink=False,
    wrong_id=False,
):
    with tempfile.TemporaryDirectory(prefix="loon-uninstall-test-") as tmp:
        root = Path(tmp)
        home = root / "user"
        home.mkdir()
        support = home / "Library/Application Support/LoonInspect"
        support.mkdir(parents=True)
        (support / "inventory-sentinel").write_text("test data")
        untouched = root / "keep"
        untouched.mkdir()
        (untouched / "sentinel").write_text("retain")
        app = root / "Applications/LoonInspect.app"
        (app / "Contents").mkdir(parents=True)
        (app / "Contents/Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "other.app"
                    if wrong_id
                    else "io.loonsec.looninspect"
                }
            )
        )
        if symlink:
            (home / "Library/Caches").symlink_to(untouched, target_is_directory=True)
        keys = root / "keys"
        keys.mkdir()
        for key in [
            "ENCRYPTION_KEY",
            "postgres-looninspect_app",
            "postgres-looninspect",
        ]:
            (keys / key).touch()
        functions = """
        uname() { printf 'Darwin\\n'; }
        hostname() { printf 'isolated-test\\n'; }
        ps() { if [ "$TEST_MODE" = busy ]; then printf '123 /test/LoonInspect.app/Contents/MacOS/LoonInspect\\n'; fi; printf '999 /usr/bin/awk -v support=%s /postgres/\\n' "$HOME/Library/Application Support/LoonInspect/pgdata"; return 0; }
        kill() { :; }
        sleep() { :; }
        defaults() { return 1; }
        security() {
            local action="$1" account="$5"
            [ "$TEST_MODE" != locked ] || return 36
            if [ "$action" = find-generic-password ]; then
                [ -e "$TEST_KEYS/$account" ] && return 0
                return 44
            fi
            [ -e "$TEST_KEYS/$account" ] || return 44
            /bin/rm -- "$TEST_KEYS/$account"
        }
        rm() {
            local target="${!#}"
            case "$target" in "$TEST_ROOT"/*) ;; *) printf 'UNSAFE PATH %s\\n' "$target"; return 99;; esac
            /bin/rm "$@"
        }
        """
        test_source = source.replace(
            "export PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "export PATH=/usr/bin:/bin:/usr/sbin:/sbin\n" + functions,
        )
        test_source = test_source.replace(
            "'/Applications/LoonInspect.app'", shlex.quote(str(app))
        )
        test_source = test_source.replace(
            'socket_dir="/tmp/io.loonsec.looninspect.$user_uid"',
            'socket_dir="$TEST_ROOT/socket"',
        )
        script = root / "test.command"
        script.write_text(test_source)
        env = dict(
            os.environ,
            HOME=str(home),
            TEST_ROOT=str(root),
            TEST_KEYS=str(keys),
            TEST_MODE=mode,
        )
        result = subprocess.run(
            ["/bin/bash", str(script), *(["--dry-run"] if dry else [])],
            check=False,
            input=answer,
            text=True,
            capture_output=True,
            env=env,
        )
        success = (
            mode == "ok"
            and not dry
            and not symlink
            and not wrong_id
            and answer == "ERASE LOONINSPECT\n"
        )
        if success:
            assert result.returncode == 0, result.stdout + result.stderr
            assert (
                not support.exists() and not app.exists() and not list(keys.iterdir())
            )
            assert "UNINSTALL COMPLETE." in result.stdout
        else:
            assert result.returncode == (0 if dry else 1), result.stdout + result.stderr
            assert (
                (support / "inventory-sentinel").exists()
                and app.exists()
                and len(list(keys.iterdir())) == 3
            )
            assert "UNINSTALL COMPLETE." not in result.stdout
        assert (untouched / "sentinel").read_text() == "retain"
        print("PASS", name)


@unittest.skipUnless(sys.platform == "darwin", "uses macOS stat and PlistBuddy")
class UninstallTests(unittest.TestCase):
    def test_complete_removal(self):
        run_case("complete removal is scoped to selected data, app and keys")

    def test_dry_run(self):
        run_case("dry run changes nothing", dry=True)

    def test_missing_confirmation(self):
        run_case("missing confirmation changes nothing", answer="")

    def test_wrong_confirmation(self):
        run_case("wrong confirmation changes nothing", answer="NO\n")

    def test_running_service(self):
        run_case("running service blocks removal", mode="busy")

    def test_locked_keychain(self):
        run_case("locked keychain blocks removal", mode="locked")

    def test_redirected_parent(self):
        run_case("redirected Library folder blocks removal", symlink=True)

    def test_different_app_identity(self):
        run_case("different app identity blocks removal", wrong_id=True)


if __name__ == "__main__":
    unittest.main()
