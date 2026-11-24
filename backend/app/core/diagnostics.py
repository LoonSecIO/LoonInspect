"""Database failure messages shared by request logs and persisted run diagnostics."""

from __future__ import annotations

import re

from sqlalchemy.exc import SQLAlchemyError


def database_error_message(exc: BaseException) -> str | None:
    """Describe a database failure without its SQL, parameters or server detail.

    Driver messages can contain the rejected value even when SQLAlchemy hides bound
    parameters. Wrappers and exception groups keep the same rule for their causes.
    A context hidden by `raise ... from None` is skipped, as Python's traceback skips
    it: that error was replaced by a fixed sentence such as a retry instruction.
    """
    pending = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, SQLAlchemyError):
            code = getattr(getattr(current, "orig", None), "sqlstate", None)
            code = code if isinstance(code, str) and re.fullmatch(r"[0-9A-Z]{5}", code) else None
            identity = type(current).__name__ + (f"; SQLSTATE {code}" if code else "")
            return (
                f"The database operation failed ({identity}). Check database health and that this build's migrations "
                "completed. If it repeats, report the run or request ID and the error type/code."
            )
        context = None if current.__suppress_context__ else current.__context__
        pending.extend(cause for cause in (current.__cause__, context) if cause is not None)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
    return None


def error_text(exc: BaseException) -> str:
    """Keep existing operator errors while withholding database values before storage."""
    return database_error_message(exc) or str(exc)
