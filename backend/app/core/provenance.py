"""Displayable source URLs, separate from credential-bearing transport configuration."""

from urllib.parse import urlsplit, urlunsplit


def source_url(value: str) -> str:
    """Remove userinfo, query and fragment from a named provenance URL.

    This is presentation only, never a replacement for the configured fetch URL. An
    unreadable address is withheld entirely rather than echoing it as an error value.
    """
    if not isinstance(value, str) or any(ord(char) <= 32 for char in value):
        return ""
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return ""
        # Accessing port catches malformed authorities without copying their text.
        _ = parts.port
        if "@" not in parts.netloc and "?" not in value and "#" not in value:
            return value
        authority = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parts.scheme, authority, parts.path, "", ""))
    except ValueError:
        return ""


def source_options(options: list[dict]) -> list[dict]:
    """Copy catalog options, changing only their named source-URL fields."""
    return [{**option, "url": source_url(option["url"])} if "url" in option else dict(option) for option in options]
