"""The browser smoke tests' Playwright pins (tests/browser/) name one release.

The npm package starts a browser build that only the image of the same release holds, so a
bump to one pin alone fails every smoke test on a missing executable, minutes into CI's Docker
image job. This says which pins disagree in the time a unit test takes. Nothing proposes these
bumps: move package.json, package-lock.json and the Dockerfile's FROM line together.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

BROWSER = Path(__file__).resolve().parents[2] / "tests" / "browser"
IMAGE = re.compile(r"FROM mcr\.microsoft\.com/playwright:v(\d+\.\d+\.\d+)-noble@sha256:[0-9a-f]{64}$", re.M)


def test_the_playwright_package_and_image_are_one_release():
    package = json.loads((BROWSER / "package.json").read_text())["devDependencies"]["@playwright/test"]
    locked = json.loads((BROWSER / "package-lock.json").read_text())["packages"]
    image = IMAGE.search((BROWSER / "Dockerfile").read_text())
    assert image, "tests/browser/Dockerfile must name the Playwright image by release and digest: vX.Y.Z-noble@sha256:..."
    pins = {"package.json": package, "Dockerfile image": image[1]}
    pins |= {
        f"package-lock.json {name}": locked[f"node_modules/{name}"]["version"]
        for name in ("@playwright/test", "playwright", "playwright-core")
    }
    assert set(pins.values()) == {package}, f"the Playwright pins in tests/browser/ name different releases: {pins}"
