from __future__ import annotations

from app.mdm.patch.base import PatchCheckResult, PatchProvider
from app.schemas.payload import NormalizedApp


class LoonSecIoClient(PatchProvider):
    """LoonSecIO CVE/patch lookup by app hash.

    Not implemented yet. The intended real call:
        POST https://api.loonsec.io/v1/hashes/lookup
        {"license_key": ..., "data_sharing_enabled": ..., "hashes": [version_hash, ...]}
    returning per-hash is_compliant/patch_available booleans.

    The hashes sent are version hashes (app.core.hashing.compute_version_hash) — the
    DynamoDB partition key on the Global API side. They must be produced by exactly the
    same construction there, or every lookup misses silently.
    """

    provider = "loonsecio"

    def __init__(self, license_key: str | None, data_sharing_enabled: bool) -> None:
        self._license_key = license_key
        self._data_sharing_enabled = data_sharing_enabled

    async def check_apps(self, apps: list[NormalizedApp]) -> list[PatchCheckResult]:
        raise NotImplementedError("LoonSecIO integration is not implemented yet")
