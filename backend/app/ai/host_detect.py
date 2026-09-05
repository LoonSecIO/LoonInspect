"""Is this container running under Docker Desktop on a Mac? A hint with its evidence.

Verified from inside an ``alpine:3`` container on Docker Desktop 4.82.0 (2026-09-05):
``/proc/version`` carries ``linuxkit`` (Docker Desktop's VM kernel; Windows on the
WSL2 backend says ``microsoft-standard-WSL2`` instead, OrbStack says ``orbstack``, and
Colima, Podman and Docker Engine show a plain distro kernel), and ``/proc/cpuinfo``
carries ``CPU implementer : 0x61``, Apple's implementer id, which only an Apple
Silicon host produces. DMI (``/sys/class/dmi/id``) and the device tree were absent, so
nothing here reads them. Intel Macs lack the implementer signal, and ``x86_64`` plus
``linuxkit`` is then ambiguous with Windows on the Hyper-V backend: the verdict says
"Docker Desktop, host OS unknown" rather than guessing.

It is a hint, never a gate. The Settings > AI page pre-selects the "via Docker
Desktop" card on a full match and shows the evidence under it; every other outcome
says what was seen and leaves the choice to the operator.
"""

from __future__ import annotations

import asyncio
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

DOCKER_DESKTOP_ALIAS = "host.docker.internal"

_APPLE_IMPLEMENTER = re.compile(r"CPU implementer\s*:\s*0x61\b")


@dataclass(frozen=True)
class HostDetection:
    # docker_desktop | orbstack | wsl2 | unknown
    runtime: str
    # macos | unknown
    host_os: str
    apple_silicon: bool
    alias: str
    alias_resolves: bool
    evidence: dict[str, str] = field(default_factory=dict)

    @property
    def docker_desktop_on_macos(self) -> bool:
        return self.runtime == "docker_desktop" and self.host_os == "macos"


def _runtime_from(proc_version: str) -> str:
    text = proc_version.lower()
    if "linuxkit" in text:
        return "docker_desktop"
    if "orbstack" in text:
        return "orbstack"
    if "microsoft" in text:
        return "wsl2"
    return "unknown"


def detect(
    proc_version: str,
    cpuinfo: str,
    *,
    alias_resolves: bool,
    alias: str = DOCKER_DESKTOP_ALIAS,
) -> HostDetection:
    """The pure function: strings in, verdict and evidence out. Table-tested."""
    runtime = _runtime_from(proc_version)
    apple_silicon = bool(_APPLE_IMPLEMENTER.search(cpuinfo))
    # A VM runtime on Apple Silicon is a Mac. Apple Silicon under no recognised VM
    # (Asahi, or a runtime this table does not know) stays "unknown" on purpose.
    host_os = "macos" if apple_silicon and runtime in {"docker_desktop", "orbstack"} else "unknown"
    kernel = proc_version.split("(", 1)[0].removeprefix("Linux version ").strip()
    implementer = _APPLE_IMPLEMENTER.search(cpuinfo)
    return HostDetection(
        runtime=runtime,
        host_os=host_os,
        apple_silicon=apple_silicon,
        alias=alias,
        alias_resolves=alias_resolves,
        evidence={
            "kernel": kernel or "(unreadable)",
            "cpuImplementer": implementer.group(0).split(":", 1)[1].strip() if implementer else "(absent)",
            "alias": f"{alias} {'resolves' if alias_resolves else 'does not resolve'}",
        },
    )


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _resolves(alias: str) -> bool:
    try:
        socket.getaddrinfo(alias, None, type=socket.SOCK_STREAM)
        return True
    except (OSError, UnicodeError):
        return False


async def read_host_detection(
    *,
    proc_version_path: str = "/proc/version",
    cpuinfo_path: str = "/proc/cpuinfo",
    resolve: Callable[[str], bool] = _resolves,
) -> HostDetection:
    """The live reading. Off Linux (a developer's Mac, the pure-logic test lane) both
    files are absent, which reads as "unknown" rather than an error."""
    alias_resolves = await asyncio.to_thread(resolve, DOCKER_DESKTOP_ALIAS)
    return detect(_read(proc_version_path), _read(cpuinfo_path), alias_resolves=alias_resolves)
