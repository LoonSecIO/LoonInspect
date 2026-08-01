from __future__ import annotations

from app.mdm.patch.base import PatchCheckResult, PatchProvider
from app.schemas.payload import NormalizedApp


class LoonSecIoClient(PatchProvider):
    """LoonSecIO CVE/patch lookup by app hash.

    Not implemented yet. The intended real call:
        POST https://api.loonsec.io/v1/hashes/lookup
        {"license_key": ..., "data_sharing_enabled": ..., "hashes": [full_hash, ...]}
    returning per-hash is_compliant/patch_available booleans.
    """

    provider = "loonsecio"

    def __init__(self, license_key: str | None, data_sharing_enabled: bool) -> None:
        self._license_key = license_key
        self._data_sharing_enabled = data_sharing_enabled

    async def check_apps(self, apps: list[NormalizedApp]) -> list[PatchCheckResult]:
        raise NotImplementedError("LoonSecIO integration is not implemented yet")
