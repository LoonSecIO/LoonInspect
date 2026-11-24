"""Operator diagnostics for outbound failures, without copying response bodies or URLs."""

import httpx


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


def http_failure(status: int) -> str:
    return f"HTTP {status}: {status_hint(status)} Response body withheld."


def transport_failure(exc: httpx.HTTPError) -> str:
    """Classify transport failures; exception strings can include credential-bearing URLs."""
    if isinstance(exc, httpx.TimeoutException):
        return "The endpoint timed out. Check its responsiveness, network access and request limits."
    if isinstance(exc, httpx.ConnectError):
        # Inspect known conditions without returning any of the exception's text.
        condition = str(exc).lower()
        if "certificate_verify_failed" in condition or "certificate verify failed" in condition:
            return "TLS certificate verification failed. Check the endpoint certificate, hostname and trust chain."
        if "connection refused" in condition:
            return "Connection refused. Check that the endpoint is running and its port is reachable."
        return "Connection failed. Check the endpoint address, DNS, network access and TLS certificate."
    if isinstance(exc, httpx.RemoteProtocolError):
        return "The endpoint returned an invalid HTTP response. Check the endpoint and proxy service logs."
    return "The request could not reach a complete response. Check the configured endpoint and network access."
