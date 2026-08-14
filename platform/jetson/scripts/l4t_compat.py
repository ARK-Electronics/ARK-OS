"""L4T / JetPack helpers shared by the Jetson GPIO operator scripts."""

from __future__ import annotations

import re

_NV_TEGRA_RELEASE = "/etc/nv_tegra_release"


def l4t_release() -> int | None:
    """Return the L4T major release (36, 39, ...) or None if unknown."""
    try:
        with open(_NV_TEGRA_RELEASE) as f:
            text = f.read()
    except OSError:
        return None
    match = re.search(r"\bR(\d+)\b", text)
    if not match:
        return None
    return int(match.group(1))


def vbus_is_pinmuxed() -> bool:
    """True when VBUS_DET is owned by the pinmux, not GPIO.

    JetPack 6 (R36) and later ARK device trees pinmux VBUS_DET, so driving
    board pin 32 as GPIO fails or fights the pinmux. Pre-R36 still uses GPIO.
    """
    release = l4t_release()
    return release is not None and release >= 36
