"""Safe failure reasons and next checks for inventory summary operators (#594)."""

import traceback
from pathlib import Path

REASONS = {
    "expired": "The one-hour deadline elapsed. Check queue age and provider latency on Overview.",
    "capacity": "The summary backlog is full. Check queue age, rate limits and provider capacity.",
    "disabled": "Inventory summaries or the AI master flag were disabled. Check Settings > AI and Feature Flags.",
    "configuration_changed": "Provider settings or customer instructions changed. New observations use the current settings.",
    "consent_missing": "Inference consent was revoked. Check Settings > AI before requesting another summary.",
    "stale_observation": "This observation predates the last compared snapshot. Check the source inventory timestamps.",
    "invalid_observation": (
        "Inventory identity or occurrence time is missing or invalid. Check the source outbox event and MDM collection."
    ),
    "overload": "The provider returned a rate limit. Check its capacity and the Apple FM pause setting.",
    "timeout": "The provider did not finish within the call deadline. Check endpoint responsiveness and queue age.",
    "unreachable": "The provider could not be reached. Test the saved endpoint in Settings > AI.",
    "http_status": "The provider refused the request. Test its model, key and endpoint in Settings > AI.",
    "malformed": "The provider returned an unsupported response shape. Check OpenAI-compatible API support.",
    "too_large": "The provider response exceeded the size limit. Check the model's response behavior.",
    "unsupported_number": (
        "The reply introduced a numeric token absent from the facts, including a shortened "
        "version. Check model choice or customer emphasis; full evidence remains authoritative."
    ),
    "unsupported_no_change": "The reply claimed no changes despite changed evidence. Check model choice and customer emphasis.",
    "invalid_summary": "The reply was empty, too long, multiline or contained markup. Check model choice and output behavior.",
    "endpoint_refused": (
        "Endpoint safety or key validation refused the saved configuration. Re-save and test it in Settings > AI."
    ),
    "internal_error": (
        "The summary worker encountered an unexpected error. Check the exception type and "
        "stack locations in container logs and report the summary ID."
    ),
}


def safe_exception(exc):
    # Never format the exception message or locals: either can contain a key or payload.
    return {
        "error_type": type(exc).__name__,
        "stack": [
            f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}" for frame in traceback.extract_tb(exc.__traceback__)
        ],
    }
