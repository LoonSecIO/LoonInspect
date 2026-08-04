"""Process entrypoint.

Replaces `fastapi run` so TLS mode can be decided before the server binds, and so
logging is configured before uvicorn emits its first line. fastapi-cli imports the app
module to resolve the import string *before* uvicorn applies its own dictConfig, which
meant the import-time logging setup was overwritten and the first few startup lines
escaped as plain text. Calling configure_logging() here and passing log_config=None
removes that whole class of problem.
"""

from __future__ import annotations

import logging
import sys

import uvicorn

from app.core.config import settings
from app.core.logging import configure_logging

# Named explicitly rather than __name__: this module runs as __main__, and a log line
# attributed to "__main__" tells a reader nothing.
logger = logging.getLogger("app.serve")


def main() -> int:
    configure_logging()

    ssl_options: dict[str, str] = {}

    if settings.tls_mode != "off":
        # Imported lazily so an `off` deployment never touches the TLS code path.
        from app.core.tls import ensure_certificate

        try:
            cert_path, key_path = ensure_certificate()
        except (FileNotFoundError, OSError) as exc:
            # Refuse to start rather than quietly serving plaintext on the port an
            # operator believes is encrypted.
            logger.error("TLS was requested but could not be configured: %s", exc)
            return 1

        ssl_options = {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key_path)}

    scheme = "https" if ssl_options else "http"

    if settings.secure_cookies and scheme == "http":
        # The failure this prevents is nasty: login returns 200, the browser silently
        # discards the Secure cookie, and every later request 401s with nothing in the
        # logs explaining why. Localhost is exempt in modern browsers, which is why
        # this is a warning and not a refusal — it works fine on a laptop.
        logger.warning(
            "secure_cookies is on but this process is serving plain HTTP. Sign-in will "
            "work on localhost, but any other hostname will silently fail to keep the "
            "session cookie. Terminate TLS in front of this container, set "
            "TLS_MODE=self-signed, or set SECURE_COOKIES=false for a deliberate "
            "plain-HTTP deployment."
        )

    logger.info(
        "binding",
        extra={
            "scheme": scheme,
            "host": settings.host,
            "port": settings.port,
            "tls_mode": settings.tls_mode,
            "forwarded_allow_ips": settings.forwarded_allow_ips,
        },
    )

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        # Makes the real client address available to the audit log when a proxy sits in
        # front. forwarded_allow_ips decides whose forwarded headers are believed.
        proxy_headers=True,
        forwarded_allow_ips=settings.forwarded_allow_ips,
        # Keeps uvicorn from replacing the handlers configured above.
        log_config=None,
        access_log=False,
        **ssl_options,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
