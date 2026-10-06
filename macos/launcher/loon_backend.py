"""LoonInspect.app's backend process: `app.serve`, plus a watchdog that never leaves an orphan.

The shell (macos/shell) starts this file with the bundled Python, the backend on PYTHONPATH and
the container's settings in the environment, exactly as the image's CMD runs `python -m
app.serve`. The one addition is what Docker gives the container for free: when the process that
started it is gone. If the shell dies without stopping the backend (a crash, a SIGKILL), this
process is re-parented to launchd; the watchdog sees that within a second, sends itself the
SIGTERM a normal quit would have sent, which uvicorn answers with its graceful shutdown, and
exits outright if that has not finished within the grace period. Then it does the shell's other
half of a quit: Postgres's fast shutdown, after the backend's, as `pg_ctl stop -m fast` would.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path

GRACE_SECONDS = 20
_shell_gone = threading.Event()


def _stop_postgres() -> None:
    """SIGINT, Postgres's fast shutdown, to the postmaster the shell started, and to no other:
    a newer launch may already have stopped it and started its own, under another PID."""
    pid = os.environ.get("LOON_SHELL_POSTGRES_PID", "")
    pgdata = os.environ.get("LOON_SHELL_PGDATA", "")
    if not pid or not pgdata:
        return
    try:
        if (Path(pgdata) / "postmaster.pid").read_text().split("\n", 1)[0] == pid:
            os.kill(int(pid), signal.SIGINT)
    except OSError:
        pass


def _on_sigterm(sig: int, frame: object) -> None:
    # uvicorn hands a SIGTERM it caught back to this handler once its shutdown is done.
    if _shell_gone.is_set():
        _stop_postgres()
    signal.signal(sig, signal.SIG_DFL)
    signal.raise_signal(sig)


def _watch(parent: int) -> None:
    while os.getppid() == parent:
        time.sleep(1)
    _shell_gone.set()
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(GRACE_SECONDS)
    _stop_postgres()
    os._exit(1)


def main() -> int:
    signal.signal(signal.SIGTERM, _on_sigterm)
    threading.Thread(target=_watch, args=(os.getppid(),), name="shell-watchdog", daemon=True).start()
    from app.serve import main as serve

    return serve()


if __name__ == "__main__":
    sys.exit(main())
