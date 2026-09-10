"""The device page's footer lists the ledger's sections from a frontend mirror of the wire
registry (#300). This pins the mirror to the registry, so a section added to the wire
fails the backend lane until the page can name it too — the page and the Splunk event
must enumerate identically, and a hand-typed list cannot promise that."""

from __future__ import annotations

import re
from pathlib import Path

from app.core.wire_vocabulary import SECTION_WRAPPERS

MIRROR = Path(__file__).resolve().parents[2] / "frontend" / "src" / "features" / "devices" / "ledgerSections.ts"


def test_the_device_page_mirror_lists_the_wire_sections_in_registry_order() -> None:
    source = MIRROR.read_text()
    literal = re.search(r"LEDGER_SECTIONS = \[(.*?)\] as const", source, re.S)
    assert literal is not None, f"{MIRROR} no longer declares LEDGER_SECTIONS as a const array"
    names = re.findall(r'"([a-z_]+)"', literal.group(1))
    assert names == list(SECTION_WRAPPERS), (
        "frontend/src/features/devices/ledgerSections.ts must name exactly the keys of "
        "app.core.wire_vocabulary.SECTION_WRAPPERS, in order"
    )
