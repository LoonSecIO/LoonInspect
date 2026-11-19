# Release notes

Status: **convention**, 2026-11-18 ([#811](https://github.com/LoonSecIO/LoonInspect/issues/811)).
One file per release, `<tag>.md`, written in the pull request that prepares the release.
**macOS release** turns it into the GitHub release's body when it makes the draft
([`macos/README.md`](../../macos/README.md#release)); a candidate's draft gets one line instead.

**The header** is everything above the file's first rule, a line holding only `---`, and the
draft leaves it out. It is a `# LoonInspect <tag>: release notes` title and a `Status:` line
saying that this is the draft for the tag, that everything below the rule becomes the release's
body, and that the lines marked `*(filled in at the tag)*` are filled in then. At publication
`release.yml` appends the upgrade notes beneath the body.

**The marker** is `*(filled in at the tag)*`, written whole on one line. Any `*(filled in …)*`
is read as the marker, so the `*(filled in then)*` of older files is caught as well, and the
notes use that form for nothing else.

- On `Release commit: *(filled in at the tag)*` the draft run writes the commit it built.
- Every other marked line is a person's to fill, on the draft. The draft run's notice and summary
  list them with their count, beside whether `Publish images` has built the commit. A release
  published with one still in its body fails the publication check, which names the lines
  ([`troubleshooting.md`](../troubleshooting.md) §25); a published release's notes can still be
  edited.

[`v1.1.0.md`](v1.1.0.md) came before this convention and is a published release's record, so it
stays as it was published.
