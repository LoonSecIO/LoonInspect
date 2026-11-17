#!/usr/bin/env bash
# The Mac app's files and the GitHub release they ship on.
#
# This repository's releases are immutable: a published release takes no more files (GitHub
# answers "Cannot upload assets to an immutable release"). So the files go onto a draft, and
# publishing the draft is the release.
#
#   release-assets.sh draft   make the draft release for $TAG at $SHA from the files in $ASSETS,
#                             or refill the draft an earlier run of the same commit made
#   release-assets.sh check   after publication: $TAG carries the files and they match their sums
#
# Needs gh (signed in, or GH_TOKEN) and jq. Environment: TAG and GITHUB_REPOSITORY; for draft
# also SHA (the full commit the files were built from), ASSETS (the directory holding the disk
# image, the zip and SHA256SUMS) and, optionally, NOTES_ROOT (a checkout whose
# docs/releases/<tag>.md becomes the draft's notes; default: the current directory).
set -euo pipefail

fail() { echo "::error::$*"; exit 1; }
sums() { if command -v sha256sum >/dev/null 2>&1; then sha256sum --check SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi; }

mode=${1:-}
case $mode in draft | check) ;; *) echo "usage: release-assets.sh draft|check (see the comment at the top of this file)" >&2; exit 2 ;; esac
: "${GITHUB_REPOSITORY:?Set GITHUB_REPOSITORY to owner/name, the repository whose release this is.}"
[[ ${TAG:-} =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] ||
  fail "'${TAG:-}' is not a version tag (vMAJOR.MINOR.PATCH, or a candidate such as v1.2.0-rc.1; docs/BRANCHING.md §1.1), so no release was touched."
base=${TAG%%-*}
version=${base#v}
files=("LoonInspect-$version-arm64.dmg" "LoonInspect-$version-arm64.zip" SHA256SUMS)

scratch=$(mktemp -d "${TMPDIR:-/tmp}/looninspect-release-assets.XXXXXX")
trap 'rm -rf "$scratch"' EXIT

# ask <what, for the error> <gh api arguments>: leaves the answer in $answer, empty for a 404.
# Any other failure is the question going unanswered, which is never the same as "there is none".
answer=
ask() {
  local what=$1
  shift
  if answer=$(gh api "$@" 2>"$scratch/gh-error"); then return 0; fi
  if grep -q 'HTTP 404' "$scratch/gh-error"; then
    answer=
    return 0
  fi
  cat "$scratch/gh-error"
  fail "Asking GitHub for $what failed. That is not the same as there being none: the question went unanswered (see the line above). Check that this job's token may read this repository's releases (contents: write for the draft job, contents: read for the check), then run it again. Nothing was uploaded."
}

if [ "$mode" = check ]; then
  ask "the published release $TAG" "repos/$GITHUB_REPOSITORY/releases/tags/$TAG"
  [ -n "$answer" ] || fail "GitHub has no published release named $TAG, so there is nothing to check. This check runs when a release is published; if you ran it by hand, name a published tag."
  missing=
  for file in "${files[@]}"; do
    jq -e --arg name "$file" 'any(.assets[]; .name == $name)' <<<"$answer" >/dev/null || missing="$missing $file"
  done
  [ -z "$missing" ] || fail "$TAG was published without$missing, so this release does not carry the Mac app, and a published release here takes no more files (this repository's releases are immutable). The container images are not affected. To ship the Mac app, publish the next version from a draft: Actions › macOS release › Run workflow, on main, with the next tag (after a candidate, the next -rc.N), then publish the draft it makes (macos/README.md, Release)."
  gh release download "$TAG" --repo "$GITHUB_REPOSITORY" --dir "$scratch/published" \
    --pattern "${files[0]}" --pattern "${files[1]}" --pattern "${files[2]}" ||
    fail "Could not download the files published on $TAG; the lines above say why. Re-run this job: the release is not changed by it."
  (cd "$scratch/published" && sums) ||
    fail "The files published on $TAG do not match the SHA256SUMS published beside them, so the Mac app should not be installed from this release. Nothing can replace a published file here: publish the next version from a fresh draft (macos/README.md, Release)."
  echo "::notice::$TAG carries ${files[0]}, ${files[1]} and SHA256SUMS, and both files match their sums."
  exit 0
fi

# --- draft ---------------------------------------------------------------------------------
[[ ${SHA:-} =~ ^[0-9a-f]{40}$ ]] || fail "SHA must be the full commit the files were built from; '${SHA:-}' is not one. No release was touched."
: "${ASSETS:?Set ASSETS to the directory that holds the disk image, the zip and SHA256SUMS.}"
notes_root=$(cd "${NOTES_ROOT:-.}" && pwd)
cd "$ASSETS"
for file in "${files[@]}"; do
  [ -f "$file" ] || fail "There is no $file among the built files, so there is nothing to put on a draft for $TAG. The build names its files after the version in macos/shell/Info.plist: check that $TAG is the version this commit builds. No release was touched."
done
sums >/dev/null || fail "The built files do not match their SHA256SUMS, so nothing was uploaded. Run the workflow again; if it says so again, the files were damaged between the build job and this one."

ask "the tag $TAG" "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG"
tagged=
if [ -n "$answer" ]; then
  tagged=$(jq -r '.object.sha' <<<"$answer")
  if [ "$(jq -r '.object.type' <<<"$answer")" = tag ]; then # an annotated tag: one more step to its commit
    ask "the commit the tag $TAG names" "repos/$GITHUB_REPOSITORY/git/tags/$tagged"
    tagged=$(jq -r '.object.sha // empty' <<<"$answer")
  fi
fi
ask "this repository's releases" --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100"
matches=$(jq -c --arg tag "$TAG" '.[] | select(.tag_name == $tag) | {draft, target: .target_commitish, url: .html_url}' <<<"$answer")

published=$(jq -r 'select(.draft == false) | .url' <<<"$matches" | head -n 1)
[ -z "$published" ] || fail "$TAG is already published ($published), and a published release here takes no more files: this repository's releases are immutable. Nothing was uploaded. Run the workflow again with the next version (after a candidate, the next -rc.N)."
[ -z "$tagged" ] || [ "$tagged" = "$SHA" ] ||
  fail "The tag $TAG already names $tagged, not $SHA, the commit these files were built from, and a published tag never moves. Nothing was uploaded. Run the workflow again with the next version."

drafts=$(jq -c 'select(.draft == true)' <<<"$matches")
count=$(grep -c . <<<"$drafts" || true)
if [ "$count" -gt 1 ]; then
  fail "There are $count drafts named $TAG, so it is not clear which one to fill. Nothing was uploaded. Delete the stale ones under Releases, leave one or none, and run the workflow again."
elif [ "$count" -eq 1 ]; then
  target=$(jq -r '.target' <<<"$drafts")
  [ "$target" = "$SHA" ] ||
    fail "The draft for $TAG ($(jq -r '.url' <<<"$drafts")) was made from $target, not from $SHA, the commit this run built. Nothing was uploaded. If that draft is stale, delete it under Releases and run the workflow again; if it is the one you mean to release, publish it instead."
  gh release upload "$TAG" --repo "$GITHUB_REPOSITORY" --clobber "${files[@]}" ||
    fail "GitHub refused the files for the draft of $TAG; the lines above say why. The draft is still a draft: run the workflow again, and a second run replaces its files."
  did="An earlier run's draft for this commit was found, and its three files were replaced; its title and notes were left as they were."
else
  if [ "$TAG" != "$base" ]; then
    echo "Release candidate for $base. It exists to prove the release workflows at a publication; use $base when it is published." >"$scratch/body.md"
    body="a one-line candidate note"
  elif [ -f "$notes_root/docs/releases/$TAG.md" ]; then
    if grep -qx -- '---' "$notes_root/docs/releases/$TAG.md"; then # the notes are what follows the file's first rule
      awk 'seen; /^---$/ { seen = 1 }' "$notes_root/docs/releases/$TAG.md" >"$scratch/body.md"
    else
      cp "$notes_root/docs/releases/$TAG.md" "$scratch/body.md"
    fi
    body="docs/releases/$TAG.md"
  else
    echo "docs/releases/$TAG.md was not found at $SHA, so this draft has no release notes yet. Write them here before publishing." >"$scratch/body.md"
    body="a placeholder, because docs/releases/$TAG.md was not found"
  fi
  flags=(--draft --target "$SHA" --title "LoonInspect $TAG" --notes-file "$scratch/body.md")
  [ "$TAG" = "$base" ] || flags+=(--prerelease)
  gh release create "$TAG" --repo "$GITHUB_REPOSITORY" "${flags[@]}" "${files[@]}" ||
    fail "GitHub refused the draft release for $TAG; the lines above say why. If a draft named $TAG now exists under Releases without its three files, run the workflow again: a second run of the same commit fills it. Nothing is published."
  did="A draft was made with its notes from $body."
fi

# Read the draft back: the three files are on it, whole.
ask "the draft just written" --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100"
draft=$(jq -c --arg tag "$TAG" '.[] | select(.tag_name == $tag and .draft == true)' <<<"$answer" | head -n 1)
[ -n "$draft" ] || fail "GitHub took the files and then listed no draft named $TAG. Look under Releases: if a draft is there, check that it holds ${files[*]}; if none is, run the workflow again."
for file in "${files[@]}"; do
  size=$(wc -c <"$file" | tr -d ' ')
  held=$(jq -r --arg name "$file" '.assets[] | select(.name == $name and .state == "uploaded") | .size' <<<"$draft")
  [ "$held" = "$size" ] ||
    fail "The draft for $TAG does not hold $file whole (GitHub reports '${held:-no such file}', the built file is $size bytes). Run the workflow again: the draft is still a draft, and a second run replaces its files."
done
url=$(jq -r '.html_url' <<<"$draft")
message="Draft release $TAG is ready: $url. It holds ${files[0]}, ${files[1]} and SHA256SUMS, built from $SHA. $did Nothing is published: read the draft, then publish it. Publishing creates the tag at that commit and starts Release, which tags and copies the container images."
echo "::notice::$message"
[ -z "${GITHUB_STEP_SUMMARY:-}" ] || echo "$message" >>"$GITHUB_STEP_SUMMARY"
