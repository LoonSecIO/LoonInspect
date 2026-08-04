from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.core.context import get_actor, get_request_id
from app.core.redact import redact

# Attributes the logging module puts on every LogRecord. Anything on a record that
# isn't in here arrived via `extra=` at the call site and belongs in the structured
# payload, which is what lets callers attach arbitrary fields without a custom record
# class. `taskName` is 3.12+; listing it unconditionally is harmless on older runtimes.
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
        # Injected by ContextFilter and rendered explicitly rather than as an extra.
        "request_id",
        "actor_type",
        "actor_label",
        # uvicorn attaches an ANSI-escaped duplicate of the message to its own records;
        # useful for its console handler, pure noise once the line is JSON.
        "color_message",
    }
)


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    return {
        key: value for key, value in record.__dict__.items() if key not in _RESERVED_RECORD_ATTRS
    }


def _timestamp(record: logging.LogRecord) -> str:
    moment = datetime.fromtimestamp(record.created, tz=timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ContextFilter(logging.Filter):
    """Copies the current request id and actor onto each record.

    A filter rather than formatter logic so the values are available to any handler or
    formatter attached later, including the audit handler in a future phase.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        actor = get_actor()
        # Anonymous is the default for everything in this phase; emitting it on every
        # line would be pure noise, so only surface an actor once one is actually set.
        if actor.type != "anonymous":
            record.actor_type = actor.type
            record.actor_label = actor.label
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": _timestamp(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id

        actor_type = getattr(record, "actor_type", None)
        if actor_type:
            payload["actor"] = {"type": actor_type, "label": getattr(record, "actor_label", "-")}

        extras = _extras(record)
        if extras:
            payload.update(redact(extras))

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # default=str so a stray datetime or Enum in `extra` degrades to a string
        # instead of taking down the log call that was trying to report a problem.
        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable equivalent for local development. Same fields, less quoting."""

    def format(self, record: logging.LogRecord) -> str:
        parts = [
            _timestamp(record),
            f"{record.levelname:<7}",
            record.name,
        ]

        request_id = getattr(record, "request_id", None)
        if request_id:
            parts.append(f"[{request_id[:8]}]")

        parts.append(record.getMessage())

        extras = _extras(record)
        if extras:
            parts.append(json.dumps(redact(extras), default=str))

        line = " ".join(parts)
        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        return line


def configure_logging() -> None:
    """Install a single stdout handler for the whole process.

    Called at import time in app.main so that lifespan and startup failures are
    formatted the same way as request logs.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(ContextFilter())
    handler.setFormatter(
        JsonFormatter() if settings.resolved_log_format == "json" else ConsoleFormatter()
    )

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level)

    # uvicorn installs its own handlers with its own format. Left alone, every line
    # would appear twice — once as JSON through our handler, once as uvicorn's plain
    # text — so hand its loggers back to the root handler.
    for name in ("uvicorn", "uvicorn.error", "fastapi"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True

    # uvicorn.access duplicates what RequestContextMiddleware already logs, minus the
    # request id and duration. Suppress the access lines, keep anything more serious.
    access = logging.getLogger("uvicorn.access")
    access.handlers = []
    access.propagate = True
    access.setLevel(logging.WARNING)

    # Both are chatty at INFO: apscheduler logs every job tick, httpx logs every
    # outbound call including the per-device MDM fetches during a sync sweep.
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
