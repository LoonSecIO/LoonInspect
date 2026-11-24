"""Operator diagnostics for outbound failures, without copying response bodies or URLs."""

import socket
import ssl

import httpx

CONNECTION_REFUSED = "Connection refused. Check that the endpoint is running and its port is reachable."
NAME_NOT_RESOLVED = "The endpoint's host name did not resolve. Check the configured address and DNS."
TLS_NOT_VERIFIED = "TLS certificate verification failed. Check the endpoint certificate, hostname and trust chain."
CONNECTION_FAILED = "Connection failed. Check the endpoint address, DNS, network access and TLS certificate."


def status_hint(status: int) -> str:
    if status == 401:
        return "The endpoint rejected authentication. Check the saved key and its expiry."
    if status == 403:
        return "The endpoint refused access. Check the key's permissions and the configured endpoint."
    if status == 404:
        return "The endpoint did not find this route or resource. Check the configured address and resource."
    if status == 413:
        return "The endpoint refused the request size. Check its ingestion limit and the configured batch size."
    if status == 429:
        return "The endpoint is rate-limiting requests. Check its capacity and retry after its limit resets."
    if 300 <= status < 400:
        return "The endpoint redirected; redirects are not followed. Check the configured address."
    if status >= 500:
        return "The endpoint could not complete the request. Check its availability and service logs."
    return "The endpoint refused the request. Check its expected format, resource settings and service logs."


def http_failure(status: int, hint: str | None = None) -> str:
    """`hint` replaces the generic next check where a path has its own (the sharing exchange carries no key)."""
    return f"HTTP {status}: {hint or status_hint(status)} Response body withheld."


def _behind(exc: BaseException) -> list[BaseException]:
    """`exc` and every exception behind it: causes, contexts and exception-group members, each once."""
    seen: set[int] = set()
    found: list[BaseException] = []
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        found.append(current)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        pending.extend((current.__cause__, current.__context__))
    return found


def transport_failure(exc: httpx.HTTPError) -> str:
    """Classify transport failures; exception strings can include credential-bearing URLs."""
    if isinstance(exc, httpx.TimeoutException):
        return "The endpoint timed out. Check its responsiveness, network access and request limits."
    if isinstance(exc, httpx.ConnectError):
        # Read by the exception types behind it, never returning any of their text. The words
        # on top cannot tell DNS from a refusal: anyio raises a refused port as "All connection
        # attempts failed", with ConnectionRefusedError only as its cause (one per address, in
        # an exception group, when the name has several).
        behind = _behind(exc)
        condition = str(exc).lower()  # the fallback, for a transport that raises no cause
        if any(isinstance(e, ssl.SSLCertVerificationError) for e in behind) or any(
            words in condition for words in ("certificate_verify_failed", "certificate verify failed")
        ):
            return TLS_NOT_VERIFIED
        if any(isinstance(e, socket.gaierror) for e in behind):
            return NAME_NOT_RESOLVED
        if any(isinstance(e, ConnectionRefusedError) for e in behind) or "connection refused" in condition:
            return CONNECTION_REFUSED
        return CONNECTION_FAILED
    if isinstance(exc, httpx.RemoteProtocolError):
        return "The endpoint returned an invalid HTTP response. Check the endpoint and proxy service logs."
    return "The request could not reach a complete response. Check the configured endpoint and network access."
