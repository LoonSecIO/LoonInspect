"""The repository rulesets under .github/rulesets, as GitHub's rulesets API takes them.

apply-repo-config.sh creates or updates each one from its file, found by the name the file
carries (docs/BRANCHING.md §8.1), and nothing reads a file before GitHub does on the
maintainer's next run. So the shape is held here: JSON, an active branch or tag target, a
name no other file uses, and a line in the script that applies the file under that name.

release-tags.json (#672) exists because ops/aws/images.template.yml's push role trusts `v*`
tags (#671): whoever can push one can assume that role from a workflow on it. So every tag
the role's trust admits has to be one only the repository admin role can create, move or
delete. The two sides match differently: IAM's StringLike `*` crosses a slash and a
ruleset's does not (GitHub matches with Ruby's File.fnmatch under FNM_PATHNAME), so
`refs/tags/v*` alone would leave `v2/x` to anyone with write access.
"""

from __future__ import annotations

import json
import re

from tests.test_ops_templates import IMAGES, OPS_AWS, REPO, load

RULESETS = REPO / ".github" / "rulesets"
SCRIPT = REPO / ".github" / "scripts" / "apply-repo-config.sh"
RELEASE_TAGS = RULESETS / "release-tags.json"

# A bypass list names a base repository role by id: maintain 2, write 4, admin 5.
REPOSITORY_ADMIN = {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}

# Tag names a push could carry: releases, near misses, and the slashes git allows in a tag.
TAG_NAMES = ("v2.0.0", "v2.0.0-rc.1", "v10.4.1", "v", "vendor", "v2/x", "v2.0.0/a/b", "2.0.0", "x/v2.0.0")


def _iam_like(pattern: str, value: str) -> bool:
    """IAM's StringLike: `*` is any run of characters, a slash included, and `?` any one character."""
    return re.fullmatch(re.escape(pattern).replace(r"\*", ".*").replace(r"\?", "."), value) is not None


def _ruleset_matches(pattern: str, ref: str) -> bool:
    """A ruleset's ref pattern as File.fnmatch reads it with FNM_PATHNAME: `*` and `?` stop at a
    slash, and only a whole `**/` segment spans directories. (Ruby's `*` also skips a segment's
    leading dot; git refuses such a ref name, so this translation leaves that out.)"""
    regex, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i) and (i == 0 or pattern[i - 1] == "/"):
            regex, i = regex + "(?:[^/]+/)*", i + 3
        else:
            regex, i = regex + {"*": "[^/]*", "?": "[^/]"}.get(pattern[i], re.escape(pattern[i])), i + 1
    return re.fullmatch(regex, ref) is not None


def test_the_matchers_read_patterns_as_github_and_iam_do():
    # GitHub's own examples for ruleset patterns, then the difference release-tags.json answers.
    assert _ruleset_matches("qa/*", "qa/foo") and not _ruleset_matches("qa/*", "qa/foo/bar")
    assert _ruleset_matches("qa/**/*", "qa/foo/bar/foobar/hello-world")
    assert _iam_like("refs/tags/v*", "refs/tags/v2/x") and not _ruleset_matches("refs/tags/v*", "refs/tags/v2/x")


def test_each_ruleset_is_active_uniquely_named_and_applied_by_the_script_under_that_name():
    rulesets = {path.name: json.loads(path.read_text()) for path in sorted(RULESETS.glob("*.json"))}
    assert {"main.json", "release-tags.json"} <= set(rulesets)
    names = [ruleset["name"] for ruleset in rulesets.values()]
    assert len(names) == len(set(names)), f"two files share a name, so the script would apply both to one ruleset: {names}"
    lines = SCRIPT.read_text().splitlines()
    for file, ruleset in rulesets.items():
        assert ruleset["target"] in {"branch", "tag"} and ruleset["enforcement"] == "active", file
        assert ruleset["conditions"]["ref_name"]["include"] and all(rule["type"] for rule in ruleset["rules"]), file
        # The script finds the ruleset to update by this name; a name it never passes adds a copy.
        call = f"apply_ruleset {ruleset['name']} {file} "
        assert any(line.startswith(call) for line in lines), f"apply-repo-config.sh has no `{call}…` line"


def test_release_tags_leave_every_v_tag_to_the_repository_admin_role():
    ruleset = json.loads(RELEASE_TAGS.read_text())
    assert ruleset["target"] == "tag"
    assert "refs/tags/v*" in ruleset["conditions"]["ref_name"]["include"]
    assert ruleset["conditions"]["ref_name"]["exclude"] == []
    assert sorted(rule["type"] for rule in ruleset["rules"]) == ["creation", "deletion", "update"]
    # A bypass covers every rule in its ruleset: the admin role creates a release's tag, and can
    # still delete one release.yml refuses; nobody else creates, moves or deletes a v* tag.
    assert ruleset["bypass_actors"] == [REPOSITORY_ADMIN]


def test_every_tag_the_push_role_trusts_is_one_only_the_admin_role_can_push():
    # The trust as deployed: the template's default, and the line ops/aws/README.md §1 deploys with.
    deploy = re.search(r"OidcSubjectPatterns=([^\"\s]+)", (OPS_AWS / "README.md").read_text())
    assert deploy, "ops/aws/README.md §1 no longer gives the OidcSubjectPatterns deploy line"
    trust = [*load(IMAGES)["Parameters"]["OidcSubjectPatterns"]["Default"].split(","), *deploy.group(1).split(",")]
    repos = {pattern.split(":ref:")[0] for pattern in trust if ":ref:" in pattern}  # the plain and the ID-stamped form
    trusted = {name for name in TAG_NAMES for repo in repos if any(_iam_like(p, f"{repo}:ref:refs/tags/{name}") for p in trust)}
    # Read, not assumed: the trust admits release tags today, a tag with a slash in it among them.
    assert {"v2.0.0", "v2/x"} <= trusted
    include = json.loads(RELEASE_TAGS.read_text())["conditions"]["ref_name"]["include"]
    for name in sorted(trusted):
        assert any(_ruleset_matches(p, f"refs/tags/{name}") for p in include), (
            f"the push role trusts tag {name}, and release-tags.json leaves it to anyone with write access"
        )
