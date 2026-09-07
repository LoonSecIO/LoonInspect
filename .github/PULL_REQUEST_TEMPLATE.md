## Description

<!-- The problem, and the outcome a user sees. Link issues with "Closes #N". -->

## Scope

<!-- What this deliberately includes, and what it deliberately leaves out. -->

## Validation

<!-- The exact commands run and where (host, container, CI), the manual checks, whether RUN_DB_TESTS=1 was set, and what was NOT run. Required: the "PR body" check fails an empty section. -->

## Risk

<!-- Compatibility, security, data, wire vocabulary or schema, migration. "None" is an answer; say why. -->

## Measurement

<!-- The one line CONTRIBUTING.md asks of every pull request: the nightly posture keys (docs/posture-snapshot.md) this change adds, activates or retires. `none` is a first-class answer. -->
posture_snapshot:

## Checklist

- [ ] I have read the [Contributing Guidelines](https://github.com/LoonSecIO/LoonInspect/blob/main/CONTRIBUTING.md).
- [ ] New or existing tests cover the change.
- [ ] Relevant docs are updated, and KNOWN_ISSUES.md is updated if a measured limit changed.
- [ ] docs/splunk-wire-vocabulary.md is updated, additively only, if any event shape changed.
- [ ] I checked the diff, changed filenames, and commit messages for credentials, private data, internal URLs, and generated artifacts.
- [ ] I recorded the validation commands and results above, including what was not run.
- [ ] AI-assisted: yes / no — and a human has read the full diff. An agent session leaves this box unticked for the human who reads it before merge.
