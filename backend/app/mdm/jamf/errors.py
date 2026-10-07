"""Safe diagnostics for failures at the Jamf response boundary."""

import httpx


class JamfResponseError(httpx.HTTPError):
    """Jamf answered successfully, but the body is not the requested resource."""


class JamfSignInError(httpx.HTTPError):
    """Sign-in failed; optional resource reads must not swallow this failure."""


def json_object(response: httpx.Response, operation: str) -> dict:
    try:
        body = response.json()
    except (ValueError, RecursionError):
        body = None
    if not isinstance(body, dict):
        raise JamfResponseError(
            f"Jamf Pro returned an invalid {operation} response. Check the connection's base URL and run Test connection."
        )
    return body


def fetch_error(exc: BaseException) -> str:
    """A failed webhook must have a useful message even when a socket error has none."""
    if str(exc).strip():
        return str(exc)
    if isinstance(exc, httpx.TimeoutException):
        return "Timed out reading computer inventory from Jamf Pro. Check that Jamf Pro is reachable from this container."
    if isinstance(exc, httpx.HTTPError):
        return "Reading computer inventory from Jamf Pro failed. Check the connection's base URL and network access."
    return f"Computer inventory could not be recorded ({type(exc).__name__}). Check this run's container log."
