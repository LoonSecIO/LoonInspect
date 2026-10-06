"""LoonInspect.app's backend process: `app.serve`, plus a watchdog that never leaves an orphan.

The shell (macos/shell) starts this file with the bundled Python, the backend on PYTHONPATH and
the container's settings in the environment, exactly as the image's CMD runs `python -m
app.serve`. The one addition is what Docker gives the container for free: when the process that
started it is gone. If the shell dies without stopping the backend (a crash, a SIGKILL), this
process is re-parented to launchd; the watchdog sees that within a second, sends itself the
SIGTERM a normal quit would have sent, which uvicorn answers with its graceful shutdown, and
exits outright if that has not finished within the grace period.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time

GRACE_SECONDS = 20


def _watch(parent: int) -> None:
    while os.getppid() == parent:
        time.sleep(1)
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(GRACE_SECONDS)
    os._exit(1)


def main() -> int:
    threading.Thread(target=_watch, args=(os.getppid(),), name="shell-watchdog", daemon=True).start()
    from app.serve import main as serve

    return serve()


if __name__ == "__main__":
    sys.exit(main())
