"""Detecting Docker Desktop on macOS from inside the container (#319): a table over
the strings a real probe container produced on 2026-09-05, plus the off-Linux path.
"""

from __future__ import annotations

import pytest

from app.ai.host_detect import detect, read_host_detection

LINUXKIT = (
    "Linux version 6.12.76-linuxkit (root@buildkitsandbox) "
    "(gcc (Alpine 15.2.0) 15.2.0, GNU ld (GNU Binutils) 2.45) #1 SMP"
)
WSL2 = "Linux version 5.15.167.4-microsoft-standard-WSL2 (root@f9c826d24240)"
WSL2 += " (gcc (GCC) 11.2.0) #1 SMP"
ORBSTACK = "Linux version 6.14.0-orbstack-00299-g1234567 (root@orbstack) (gcc 14) #1 SMP"
UBUNTU = "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-047) (x86_64-linux-gnu-gcc-13)"
UBUNTU += " #45-Ubuntu SMP"

APPLE_CPU = "processor\t: 0\nBogoMIPS\t: 48.00\nCPU implementer\t: 0x61\nCPU architecture: 8\n"
APPLE_CPU += "CPU variant\t: 0x0\nCPU part\t: 0x000\n"
ARM_CPU = "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: 0xd0c\n"
INTEL_CPU = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Core(TM) i9\n"


@pytest.mark.parametrize(
    ("proc_version", "cpuinfo", "runtime", "host_os", "apple_silicon", "full_match"),
    [
        (LINUXKIT, APPLE_CPU, "docker_desktop", "macos", True, True),
        # Intel Mac or Windows on the Hyper-V backend: Docker Desktop, host unknown.
        (LINUXKIT, INTEL_CPU, "docker_desktop", "unknown", False, False),
        (WSL2, INTEL_CPU, "wsl2", "unknown", False, False),
        (ORBSTACK, APPLE_CPU, "orbstack", "macos", True, False),
        # Colima, Podman, Engine: a plain distro kernel says nothing about the host.
        (UBUNTU, APPLE_CPU, "unknown", "unknown", True, False),
        (UBUNTU, ARM_CPU, "unknown", "unknown", False, False),
        ("", "", "unknown", "unknown", False, False),
    ],
)
def test_the_table(proc_version, cpuinfo, runtime, host_os, apple_silicon, full_match):
    d = detect(proc_version, cpuinfo, alias_resolves=True)
    assert (d.runtime, d.host_os, d.apple_silicon, d.docker_desktop_on_macos) == (runtime, host_os, apple_silicon, full_match)


def test_the_evidence_names_what_was_seen():
    d = detect(LINUXKIT, APPLE_CPU, alias_resolves=True)
    assert d.evidence["kernel"] == "6.12.76-linuxkit"
    assert d.evidence["cpuImplementer"] == "0x61"
    assert d.evidence["alias"] == "host.docker.internal resolves"
    absent = detect("", "", alias_resolves=False)
    assert absent.evidence["kernel"] == "(unreadable)"
    assert absent.evidence["cpuImplementer"] == "(absent)"
    assert absent.evidence["alias"].endswith("does not resolve")


async def test_off_linux_reads_as_unknown_not_as_an_error(tmp_path):
    d = await read_host_detection(
        proc_version_path=str(tmp_path / "no-version"),
        cpuinfo_path=str(tmp_path / "no-cpuinfo"),
        resolve=lambda _alias: False,
    )
    assert d.runtime == "unknown"
    assert d.alias_resolves is False
