"""docker-compose.yml passes every setting the app reads, at config.py's own default (#707).

Kyle, 2026-09-27: "I want as much in docker-compose as possible." On the shipped stack the
app service's `environment:` is the whole of what reaches the app: a setting it does not
pass cannot be set in `.env` at all, whatever `.env` says. So every field of
`app.core.config.Settings` is passed as `NAME: ${NAME:-default}` or named, with its reason,
under the block's closing "Not passed, on purpose:" line, and a passed default is what the
app would have run with had the variable been absent. Defaults are compared after the app's
own parse — `Settings` reading them from the environment — so `true`, `1.0` and `[]` are
held to `True`, `1.0` and `[]`, not to a spelling.

Pure: no database and no Docker; the compose files are read from disk.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from unittest import mock

import pytest
import yaml
from pydantic import ValidationError
from pydantic_settings import BaseSettings, SettingsError

from app.core.config import Settings

REPO = Path(__file__).resolve().parents[2]
COMPOSE = (REPO / "docker-compose.yml").read_text()

DEFAULTED = re.compile(r"\$\{(?P<name>\w+):-(?P<default>[^}]*)\}")
NOT_PASSED_HEAD = "# Not passed, on purpose:"
NOT_PASSED_LINE = re.compile(r"\s*#\s+(?P<names>[A-Z][A-Z0-9_]*(?:, [A-Z][A-Z0-9_]*)*)\s{2,}\S.*")
# Passed, and not at a default: the bundled database's address, which the file builds from
# POSTGRES_APP_PASSWORD, and the key compose refuses to start without (`:?`).
NOT_AT_A_DEFAULT = {"DATABASE_URL", "ENCRYPTION_KEY"}


class ComposeLoader(yaml.SafeLoader):
    """SafeLoader plus Compose's `!reset`, which both override files use."""


ComposeLoader.add_constructor("!reset", lambda loader, node: None)


def _passed(text: str) -> dict:
    return yaml.load(text, Loader=ComposeLoader)["services"]["app"].get("environment") or {}


def _not_passed(text: str) -> set[str]:
    lines = text.splitlines()
    heads = [i for i, line in enumerate(lines) if line.strip() == NOT_PASSED_HEAD]
    assert len(heads) == 1, f"docker-compose.yml should close the app's environment with one {NOT_PASSED_HEAD!r} line"
    names: set[str] = set()
    for line in lines[heads[0] + 1 :]:
        if not (match := NOT_PASSED_LINE.fullmatch(line)):
            break
        names.update(match["names"].split(", "))
    return names


def disagreements(text: str, settings: type[BaseSettings] = Settings) -> list[str]:
    """Every way a compose file and a settings class disagree, one sentence each."""
    fields = {((settings.model_config.get("env_prefix") or "") + field).upper(): field for field in settings.model_fields}
    passed, not_passed = _passed(text), _not_passed(text)
    named = passed.keys() | not_passed
    found = [f"{name} is passed and also listed as not passed" for name in sorted(passed.keys() & not_passed)]
    found += [f"{name} is in docker-compose.yml and is not a setting" for name in sorted(named - fields.keys())]
    found += [
        f"{name} is a setting that docker-compose.yml neither passes nor lists under {NOT_PASSED_HEAD!r}"
        for name in sorted(fields.keys() - named)
    ]
    defaults = {}
    for name, value in passed.items():
        if name in NOT_AT_A_DEFAULT or name not in fields:
            continue
        match = DEFAULTED.fullmatch(str(value))
        if match and match["name"] == name:
            defaults[name] = match["default"]
        else:
            found.append(f"{name} is passed as {value!r}, not as ${{{name}:-<config.py's default>}}")
    try:
        with mock.patch.dict(os.environ, defaults, clear=True):
            read = settings(_env_file=None)
    except SettingsError as refused:  # a list or JSON value that does not parse as one
        return [*found, f"the app refuses docker-compose.yml's environment: {refused}"]
    except ValidationError as refused:
        return found + [
            f"the app refuses docker-compose.yml's {'.'.join(map(str, e['loc'])) or 'settings'}: {e['msg']}"
            for e in refused.errors()
        ]
    for name, written in defaults.items():
        default = settings.model_fields[fields[name]].get_default(call_default_factory=True)
        got = getattr(read, fields[name])
        # Compose cannot pass "unset", so an optional setting goes in empty; the app tests
        # SIEM_WEBHOOK_URL and the INITIAL_ADMIN_ pair for truth, never for None.
        if got != ("" if default is None else default):
            found.append(f"{name} is {written!r} in docker-compose.yml, read by the app as {got!r}; config.py says {default!r}")
    return found


def test_every_setting_is_passed_at_its_default_or_listed_as_not_passed():
    assert disagreements(COMPOSE) == []


def test_a_default_is_held_to_what_the_app_reads_not_to_its_spelling():
    assert disagreements(COMPOSE.replace("${SECURE_COOKIES:-true}", "${SECURE_COOKIES:-yes}")) == []


@pytest.mark.parametrize(
    ("written", "drifted", "named"),
    [
        ("${SYNC_HOUR:-1}", "${SYNC_HOUR:-2}", "SYNC_HOUR is '2' in docker-compose.yml, read by the app as 2; config.py says 1"),
        ("${SECURITY_HEADERS:-true}", "${SECURITY_HEADERS:-off}", "SECURITY_HEADERS is 'off'"),
        ("${SIEM_WEBHOOK_URL:-}", "${SIEM_WEBHOOK_URL:-https://siem.example}", "config.py says None"),
        ("${SWEEP_FAILURE_MAX_PERCENT:-1.0}", "${SWEEP_FAILURE_MAX_PERCENT:-10}", "SWEEP_FAILURE_MAX_PERCENT is '10'"),
        ("SYNC_HOUR: ${SYNC_HOUR:-1}", "SYNC_HOUR: ${SYNC_HOURS:-1}", "SYNC_HOUR is passed as '${SYNC_HOURS:-1}'"),
        ("${LOG_LEVEL:-INFO}", "${LOG_LEVEL:-LOUD}", "the app refuses docker-compose.yml's log_level"),
        ("${DESTINATION_ALLOWED_HOSTS:-[]}", "${DESTINATION_ALLOWED_HOSTS:-}", '"destination_allowed_hosts"'),
        ("#   DEBUG ", "#   DEBUGGING ", "DEBUGGING is in docker-compose.yml and is not a setting"),
    ],
)
def test_a_default_or_a_name_that_drifts_is_named(written, drifted, named):
    assert COMPOSE.count(written) == 1
    assert any(named in line for line in disagreements(COMPOSE.replace(written, drifted)))


def test_a_new_setting_cannot_land_without_a_line_in_the_compose_file():
    class Grown(Settings):
        brand_new_knob: int = 3

    assert disagreements(COMPOSE, Grown) == [
        f"BRAND_NEW_KNOB is a setting that docker-compose.yml neither passes nor lists under {NOT_PASSED_HEAD!r}"
    ]


@pytest.mark.parametrize(
    ("override", "sets"),
    [("docker-compose.external.yml", {"DATABASE_MODE", "DATABASE_URL"}), ("docker-compose.pull.yml", set())],
)
def test_an_override_sets_nothing_beyond_its_own_job(override, sets):
    """docker-compose.yml is the whole list: an override that set anything else would change
    that setting for everyone who layers it on, with neither file saying so."""
    assert set(_passed((REPO / override).read_text())) == sets


@pytest.mark.parametrize(
    ("name", "value", "words"),
    [
        ("SYNC_HOUR", "24", "SYNC_HOUR must be between 0 and 23"),
        ("SYNC_MINUTE", "60", "SYNC_MINUTE must be between 0 and 59"),
        ("SYNC_TIMEZONE", "Chicago", "SYNC_TIMEZONE must be a time zone name as the tz database spells it"),
    ],
)
def test_a_schedule_setting_env_can_reach_is_refused_at_startup_by_name(name, value, words):
    with mock.patch.dict(os.environ, {name: value}, clear=True), pytest.raises(ValidationError) as refused:
        Settings(_env_file=None)
    assert words in str(refused.value)
