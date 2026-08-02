from __future__ import annotations

from app.core.config import settings
from app.core.version import get_app_version


def build_user_agent(comment: str, product_name: str | None = None) -> str:
    name = product_name or settings.user_agent_product_name
    return f"{name}/{get_app_version()} {comment}"
