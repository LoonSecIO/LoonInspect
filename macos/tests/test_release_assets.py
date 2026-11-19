#!/usr/bin/env python3
"""Exercise macos/scripts/release-assets.sh against a fake gh.

The script puts the Mac app's files on a draft release (this repository's releases are
immutable, so a published one takes no more files), says what the draft still owes, and, after
publication, checks that the release carries them. No network, no GitHub account and no real
release is used: a fake `gh` answers from a JSON file and records every call that would have
changed something, and any command it does not expect.

Run with python3 macos/tests/test_release_assets.py. Needs bash and jq, which macOS and the
GitHub runners both ship.
"""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = "example/looninspect"
SHA = "a" * 40
OTHER = "b" * 40
FILES = ["LoonInspect-1.2.0-arm64.dmg", "LoonInspect-1.2.0-arm64.zip", "SHA256SUMS"]
SCRIPT = Path(__file__).resolve().parents[1] / "scripts/release-assets.sh"

FAKE_GH = r"""#!/usr/bin/env python3
import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

args = sys.argv[1:]
state_path = Path(os.environ["TEST_STATE"])
state = json.loads(state_path.read_text())
repo = os.environ["GITHUB_REPOSITORY"]


def save():
    state_path.write_text(json.dumps(state))


def record(operation, **extra):
    state.setdefault("calls", []).append({"operation": operation, **extra})
    save()


def not_found():
    print(json.dumps({"message": "Not Found"}))
    print("gh: Not Found (HTTP 404)", file=sys.stderr)
    sys.exit(1)


def option(name):
    return args[args.index(name) + 1] if name in args else None


def assets(names):
    return [{"name": Path(n).name, "size": Path(n).stat().st_size, "state": "uploaded"} for n in names]


if args[:1] == ["api"]:
    path = [a for a in args[1:] if not a.startswith("--")][0]
    if state.get("fail") and state["fail"] in path:
        print("gh: Server Error (HTTP 502)", file=sys.stderr)
        sys.exit(1)
    if path == f"repos/{repo}/releases?per_page=100":
        print(json.dumps(state["releases"]))
    elif path.startswith(f"repos/{repo}/git/ref/tags/"):
        tag = path.rsplit("/", 1)[1]
        if tag not in state["tags"]:
            not_found()
        print(json.dumps({"ref": "refs/tags/" + tag, "object": state["tags"][tag]}))
    elif path.startswith(f"repos/{repo}/git/tags/"):
        print(json.dumps({"object": {"type": "commit", "sha": state["annotated"][path.rsplit("/", 1)[1]]}}))
    elif path.startswith(f"repos/{repo}/releases/tags/"):
        tag = path.rsplit("/", 1)[1]
        found = [r for r in state["releases"] if r["tag_name"] == tag and not r["draft"]]
        if not found:
            not_found()
        print(json.dumps(found[0]))
    elif path.startswith(f"repos/{repo}/actions/workflows/publish-images.yml/runs?"):
        query = parse_qs(urlsplit(path).query)
        runs = [r for r in state.get("runs", [])
                if r["head_sha"] == query["head_sha"][0] and r["conclusion"] == query["status"][0]]
        print(json.dumps({"total_count": len(runs), "workflow_runs": runs[:int(query["per_page"][0])]}))
    else:
        print("fake gh: unexpected api path " + path, file=sys.stderr)
        sys.exit(97)
elif args[:2] == ["release", "create"]:
    tag = args[2]
    files = [a for a in args[3:] if Path(a).is_file() and a != option("--notes-file")]
    record("create", tag=tag, draft="--draft" in args, prerelease="--prerelease" in args,
           target=option("--target"), title=option("--title"),
           body=Path(option("--notes-file")).read_text(), files=sorted(files))
    if state.get("refuse") == "create":
        print("HTTP 422: Validation Failed", file=sys.stderr)
        sys.exit(1)
    state["releases"].append({
        "tag_name": tag, "draft": "--draft" in args, "target_commitish": option("--target"),
        "html_url": f"https://github.example/{repo}/releases/tag/untagged-1", "assets": assets(files),
        "body": Path(option("--notes-file")).read_text(),
    })
    save()
elif args[:2] == ["release", "upload"]:
    tag = args[2]
    files = [a for a in args[3:] if Path(a).is_file()]
    record("upload", tag=tag, clobber="--clobber" in args, files=sorted(files))
    for release in state["releases"]:
        if release["tag_name"] == tag and release["draft"]:
            release["assets"] = assets(files)
    save()
elif args[:2] == ["release", "download"]:
    destination = Path(option("--dir"))
    destination.mkdir(parents=True, exist_ok=True)
    for source in Path(os.environ["TEST_PUBLISHED"]).iterdir():
        shutil.copy(source, destination / source.name)
else:
    record("unexpected", args=args)
    print("fake gh: unexpected command " + " ".join(args), file=sys.stderr)
    sys.exit(97)
"""


class ReleaseAssetsTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name)
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        (fake_bin / "gh").write_text(FAKE_GH)
        (fake_bin / "gh").chmod(0o755)
        self.state = self.root / "state.json"
        self.write_state()
        self.assets = self.build_files(self.root / "assets", "1.2.0")
        self.env = {
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "TEST_STATE": str(self.state),
            "TEST_PUBLISHED": str(self.assets),
            "GITHUB_REPOSITORY": REPO,
            "SHA": SHA,
            "ASSETS": str(self.assets),
            "NOTES_ROOT": str(self.root / "checkout"),
        }
        self.env.pop("GITHUB_STEP_SUMMARY", None)
        (self.root / "checkout/docs/releases").mkdir(parents=True)

    def tearDown(self):
        self.scratch.cleanup()

    def build_files(self, directory, version):
        directory.mkdir()
        lines = []
        for suffix in ("dmg", "zip"):
            name = f"LoonInspect-{version}-arm64.{suffix}"
            (directory / name).write_bytes(f"the {suffix} of {version}".encode())
            lines.append(f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(lines))
        return directory

    def write_state(self, releases=(), tags=None, **extra):
        self.state.write_text(json.dumps({"releases": list(releases), "tags": tags or {}, "annotated": {}, **extra}))

    def release(self, tag, *, draft, target=SHA, assets=(), body=""):
        return {
            "tag_name": tag, "draft": draft, "target_commitish": target,
            "html_url": f"https://github.example/{REPO}/releases/tag/{tag}",
            "assets": [{"name": name, "size": 1, "state": "uploaded"} for name in assets], "body": body,
        }

    def notes(self, body):
        (self.root / "checkout/docs/releases/v1.2.0.md").write_text(f"# Notes\n\nStatus: draft.\n\n---\n\n{body}")

    def run_script(self, mode, tag, **env):
        return subprocess.run(
            ["bash", str(SCRIPT), mode], env={**self.env, "TAG": tag, **env}, cwd=self.root,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False,
        )

    def notice(self, result):
        (line,) = [line for line in result.stdout.splitlines() if line.startswith("::notice::")]
        return line

    def calls(self):
        return json.loads(self.state.read_text()).get("calls", [])

    def assert_refused(self, result, *phrases):
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("::error::", result.stdout)
        for phrase in phrases:
            self.assertIn(phrase, result.stdout)
        self.assertEqual(self.calls(), [], "a refusal must not create or upload anything")

    # --- draft ---------------------------------------------------------------------------

    def test_a_release_gets_a_draft_at_the_built_commit_with_its_notes(self):
        notes = self.root / "checkout/docs/releases/v1.2.0.md"
        notes.write_text("# Notes\n\nStatus: draft.\n\n---\n\nWhat ships.\n\n---\n\nA later rule stays.\n")
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        (call,) = self.calls()
        self.assertEqual(call["operation"], "create")
        self.assertTrue(call["draft"])
        self.assertFalse(call["prerelease"])
        self.assertEqual(call["target"], SHA)
        self.assertEqual(call["title"], "LoonInspect v1.2.0")
        self.assertEqual(call["body"], "\nWhat ships.\n\n---\n\nA later rule stays.\n")
        self.assertEqual(call["files"], ["LoonInspect-1.2.0-arm64.dmg", "LoonInspect-1.2.0-arm64.zip", "SHA256SUMS"])
        self.assertIn("::notice::Draft release v1.2.0 is ready", result.stdout)
        self.assertIn("Nothing is published", result.stdout)
        self.assertIn("docs/releases/v1.2.0.md", result.stdout)

    def test_a_candidate_is_a_prerelease_with_a_one_line_note(self):
        result = self.run_script("draft", "v1.2.0-rc.1")
        self.assertEqual(result.returncode, 0, result.stdout)
        (call,) = self.calls()
        self.assertTrue(call["draft"])
        self.assertTrue(call["prerelease"])
        self.assertIn("Release candidate for v1.2.0.", call["body"])
        self.assertIn("Its notes carry no line marked to be filled in at the tag.", self.notice(result))

    def test_a_release_without_a_notes_file_says_so_in_the_draft(self):
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("docs/releases/v1.2.0.md was not found", self.calls()[0]["body"])
        self.assertIn("Its notes still carry 1 line marked", self.notice(result))

    # --- what the draft still owes -------------------------------------------------------

    def test_the_release_commit_is_written_where_the_notes_mark_it(self):
        self.notes("Release commit: *(filled in at the tag)*.\n\nWhat ships.\n")
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.calls()[0]["body"], f"\nRelease commit: `{SHA}`.\n\nWhat ships.\n")
        self.assertIn("with the commit written on its Release commit: line", self.notice(result))
        self.assertIn("Its notes carry no line marked to be filled in at the tag.", self.notice(result))

    def test_the_lines_a_person_fills_are_counted_and_quoted_and_the_draft_is_still_made(self):
        summary = self.root / "summary.md"
        self.notes("Release commit: *(filled in at the tag)*.\n\nCI run *(filled in at the tag)*, 50% of it.\n\n"
                   "Recorded at the tag *(filled in then)*: counts.\n")
        result = self.run_script("draft", "v1.2.0", GITHUB_STEP_SUMMARY=str(summary))
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([c["operation"] for c in self.calls()], ["create"])
        lines = ("    line 4: CI run *(filled in at the tag)*, 50% of it.\n"
                 "    line 6: Recorded at the tag *(filled in then)*: counts.")
        self.assertIn("Its notes still carry 2 lines marked to be filled in at the tag", self.notice(result))
        self.assertIn(lines.replace("%", "%25").replace("\n", "%0A"), self.notice(result))
        self.assertIn(f"\n\n{lines}\n\n", summary.read_text())

    def test_a_refilled_draft_is_read_for_its_notes_as_they_stand(self):
        draft = self.release("v1.2.0", draft=True, assets=["SHA256SUMS"], body="CI run *(filled in then)*.\r\n")
        self.write_state(releases=[draft])
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("still carry 1 line marked to be filled in at the tag", self.notice(result))
        self.assertIn("%0A    line 1: CI run *(filled in then)*.%0A", self.notice(result))

    def test_a_commit_publish_images_built_is_said_to_have_its_images(self):
        run = "https://github.example/actions/runs/7"
        self.write_state(runs=[{"head_sha": SHA, "conclusion": "success", "html_url": run}])
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(f"Publish images succeeded for {SHA} ({run})", self.notice(result))
        self.assertNotIn("no images yet", result.stdout)

    def test_a_commit_without_images_is_given_the_command_and_nothing_is_started(self):
        self.write_state(runs=[
            {"head_sha": OTHER, "conclusion": "success", "html_url": "https://github.example/actions/runs/8"},
            {"head_sha": SHA, "conclusion": "failure", "html_url": "https://github.example/actions/runs/9"},
        ])
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(f"No Publish images run for {SHA} has succeeded, so this commit has no images yet", self.notice(result))
        self.assertIn('run gh workflow run "Publish images" --ref main', self.notice(result))
        self.assertEqual([c["operation"] for c in self.calls()], ["create"], "the draft asks about images, never starts them")

    def test_an_unanswered_question_about_images_is_said_and_the_draft_still_stands(self):
        self.write_state(fail="actions/workflows")
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([c["operation"] for c in self.calls()], ["create"])
        self.assertIn("HTTP 502", result.stdout)
        self.assertIn(f"Publish images run of {SHA} failed. That is not the same as there being none: "
                      "the question went unanswered", self.notice(result))
        self.assertNotIn("no images yet", result.stdout)

    def test_an_existing_tag_on_the_built_commit_is_used(self):
        self.write_state(tags={"v1.2.0": {"type": "commit", "sha": SHA}})
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual([c["operation"] for c in self.calls()], ["create"])

    def test_a_second_run_of_the_same_commit_refills_its_draft(self):
        self.write_state(releases=[self.release("v1.2.0", draft=True, assets=["SHA256SUMS"])])
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 0, result.stdout)
        (call,) = self.calls()
        self.assertEqual(call["operation"], "upload")
        self.assertTrue(call["clobber"])
        self.assertIn("its title and notes were left as they were", result.stdout)

    def test_a_published_release_takes_no_more_files(self):
        self.write_state(releases=[self.release("v1.2.0", draft=False)], tags={"v1.2.0": {"type": "commit", "sha": SHA}})
        self.assert_refused(self.run_script("draft", "v1.2.0"), "v1.2.0 is already published", "immutable", "next version")

    def test_a_tag_on_another_commit_never_moves(self):
        self.write_state(tags={"v1.2.0": {"type": "commit", "sha": OTHER}})
        self.assert_refused(self.run_script("draft", "v1.2.0"), f"already names {OTHER}", "never moves")

    def test_an_annotated_tag_is_followed_to_its_commit(self):
        self.write_state(tags={"v1.2.0": {"type": "tag", "sha": "c" * 40}}, annotated={"c" * 40: OTHER})
        self.assert_refused(self.run_script("draft", "v1.2.0"), f"already names {OTHER}")

    def test_a_draft_from_another_commit_is_left_alone(self):
        self.write_state(releases=[self.release("v1.2.0", draft=True, target=OTHER)])
        self.assert_refused(self.run_script("draft", "v1.2.0"), f"was made from {OTHER}", "delete it under Releases")

    def test_two_drafts_of_one_name_are_not_guessed_between(self):
        self.write_state(releases=[self.release("v1.2.0", draft=True), self.release("v1.2.0", draft=True)])
        self.assert_refused(self.run_script("draft", "v1.2.0"), "There are 2 drafts named v1.2.0")

    def test_an_unanswered_question_is_not_read_as_no_release(self):
        self.write_state(fail="releases?per_page")
        self.assert_refused(self.run_script("draft", "v1.2.0"), "HTTP 502", "the question went unanswered")

    def test_files_that_do_not_match_their_sums_are_not_uploaded(self):
        (self.assets / "LoonInspect-1.2.0-arm64.dmg").write_bytes(b"damaged")
        self.assert_refused(self.run_script("draft", "v1.2.0"), "do not match their SHA256SUMS")

    def test_a_tag_for_another_version_than_the_built_files_is_refused(self):
        self.assert_refused(self.run_script("draft", "v1.3.0"), "There is no LoonInspect-1.3.0-arm64.dmg")

    def test_a_name_that_is_not_a_version_is_refused(self):
        self.assert_refused(self.run_script("draft", "latest"), "'latest' is not a version tag")

    def test_a_refused_draft_says_a_second_run_fills_it(self):
        self.write_state(refuse="create")
        result = self.run_script("draft", "v1.2.0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("GitHub refused the draft release for v1.2.0", result.stdout)
        self.assertIn("a second run of the same commit fills it", result.stdout)

    # --- check ---------------------------------------------------------------------------

    def test_a_published_release_with_its_files_and_no_line_left_to_fill_passes(self):
        candidate = ("Release candidate for v1.2.0. It exists to prove the release workflows at a publication;"
                     " use v1.2.0 when it is published.\n")
        self.write_state(releases=[
            self.release("v1.2.0-rc.1", draft=False, assets=FILES, body=candidate),
            self.release("v1.2.0", draft=False, assets=FILES, body=f"Release commit: `{SHA}`.\r\n"),
        ])
        for tag in ("v1.2.0-rc.1", "v1.2.0"):
            result = self.run_script("check", tag)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("both files match their sums", result.stdout)

    def test_a_release_published_with_a_line_still_marked_fails_and_names_it(self):
        body = f"Release commit: `{SHA}`.\r\n\r\nRecorded at the tag *(filled in at the tag)*: the CI run.\r\n"
        self.write_state(releases=[self.release("v1.2.0", draft=False, assets=FILES, body=body)])
        result = self.run_script("check", "v1.2.0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("::error::v1.2.0 was published with 1 line of its notes still marked to be filled in at the tag",
                      result.stdout)
        self.assertIn("the body of an immutable release can still be edited", result.stdout)
        self.assertIn("%0A    line 3: Recorded at the tag *(filled in at the tag)*: the CI run.", result.stdout)
        self.assertNotIn("%0D", result.stdout)
        self.assertNotIn("::notice::", result.stdout)

    def test_a_release_short_of_both_its_files_and_its_notes_hears_of_both(self):
        body = "Release commit: *(filled in at the tag)*.\n"
        self.write_state(releases=[self.release("v1.2.0", draft=False, assets=["SHA256SUMS"], body=body)])
        self.assert_refused(self.run_script("check", "v1.2.0"), "still marked to be filled in at the tag", "published without")

    def test_a_release_published_without_the_app_names_what_is_missing_and_the_way_out(self):
        self.write_state(releases=[self.release("v1.2.0-rc.1", draft=False, assets=["SHA256SUMS"])])
        self.assert_refused(
            self.run_script("check", "v1.2.0-rc.1"),
            "published without LoonInspect-1.2.0-arm64.dmg LoonInspect-1.2.0-arm64.zip,",
            "immutable", "The container images are not affected", "Run workflow, on main, with the next tag",
        )

    def test_published_files_that_do_not_match_their_sums_are_called_out(self):
        self.write_state(releases=[self.release("v1.2.0", draft=False, assets=FILES)])
        (self.assets / "LoonInspect-1.2.0-arm64.zip").write_bytes(b"swapped")
        result = self.run_script("check", "v1.2.0")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("do not match the SHA256SUMS published beside them", result.stdout)


if __name__ == "__main__":
    unittest.main()
