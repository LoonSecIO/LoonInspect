from __future__ import annotations

from app.mdm.patch.base import PatchCheckResult, PatchProvider
from app.schemas.payload import NormalizedApp


class JamfPatchProvider(PatchProvider):
    """Jamf Pro's Patch Reporting API (patch-software-title-configurations / patch-report).

    Not implemented yet — this is where per-title patch-report lookups would be made
    to determine whether an installed version is the latest known-good one.
    """

    provider = "jamf"

    def __init__(self, base_url: str, client_id: str | None, client_secret: str | None) -> None:
        self._base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret

    async def check_apps(self, apps: list[NormalizedApp]) -> list[PatchCheckResult]:
        raise NotImplementedError("Jamf Patch Reporting integration is not implemented yet")
