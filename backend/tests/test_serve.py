"""The entrypoint's keep-alive (#399), and the setting that feeds it.

No database. uvicorn closes an idle connection after its shipped five seconds, while a
reverse proxy or load balancer reuses its connections to the app for as long as its own
idle timeout — so behind one, a keep-alive at or under that timeout is an occasional blank
502 from a healthy app. `KEEP_ALIVE_TIMEOUT_SECONDS` is the operator's lever: these pin
that it parses, that a value out of range is refused with the rule in the sentence, and
that `app.serve` hands it to uvicorn and says so on the `binding` line.
"""

from __future__ import annotations

import logging

import pytest
from pydantic import ValidationError

from app import serve
from app.core.config import Settings, settings

_RULE = "a proxy's idle timeout must be shorter than the app's keep-alive"


def test_the_keep_alive_defaults_to_uvicorns_own_five_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KEEP_ALIVE_TIMEOUT_SECONDS", raising=False)
    assert Settings.model_fields["keep_alive_timeout_seconds"].default == 5
    assert Settings(_env_file=None).keep_alive_timeout_seconds == 5


def test_the_keep_alive_is_read_from_its_environment_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    """135 is what a pod behind pods-ingress sets: that ALB idles 130 s (#401)."""
    monkeypatch.setenv("KEEP_ALIVE_TIMEOUT_SECONDS", "135")
    assert Settings(_env_file=None).keep_alive_timeout_seconds == 135


@pytest.mark.parametrize("value", ["1", "600"])
def test_the_bounds_themselves_are_accepted(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("KEEP_ALIVE_TIMEOUT_SECONDS", value)
    assert Settings(_env_file=None).keep_alive_timeout_seconds == int(value)


@pytest.mark.parametrize("value", ["0", "601"])
def test_a_keep_alive_out_of_range_is_refused_with_the_rule(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("KEEP_ALIVE_TIMEOUT_SECONDS", value)
    with pytest.raises(ValidationError, match=_RULE) as refused:
        Settings(_env_file=None)
    assert "KEEP_ALIVE_TIMEOUT_SECONDS must be between 1 and 600 seconds" in str(refused.value)


def test_serve_hands_the_keep_alive_to_uvicorn_and_logs_it(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[dict] = []
    monkeypatch.setattr(serve.uvicorn, "run", lambda app, **kwargs: calls.append({"app": app, **kwargs}))
    # configure_logging replaces the root handlers for the whole process, pytest's
    # capture handler among them.
    monkeypatch.setattr(serve, "configure_logging", lambda: None)
    monkeypatch.setattr(settings, "tls_mode", "off")
    monkeypatch.setattr(settings, "keep_alive_timeout_seconds", 135)
    caplog.set_level(logging.INFO, logger="app.serve")

    assert serve.main() == 0

    (call,) = calls
    assert call["app"] == "app.main:app"
    assert call["timeout_keep_alive"] == 135
    (binding,) = [record for record in caplog.records if record.getMessage() == "binding"]
    assert binding.keep_alive_timeout_seconds == 135
