"""Per-user autostart registration (Windows Run key).

Only a packaged build can register itself: in a source checkout there is no single
executable to point at, and a Run key holding `python -m app` would depend on the
working directory that the registry cannot express.
"""

from __future__ import annotations

import logging
import sys

from app.meta import APP_NAME
from app.paths import is_frozen

log = logging.getLogger(__name__)

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def is_supported() -> bool:
    return sys.platform == "win32" and is_frozen()


def launch_command() -> str:
    return f'"{sys.executable}"'


def is_enabled() -> bool:
    if not is_supported():
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
        return value == launch_command()
    except OSError:
        return False


def set_enabled(enabled: bool) -> bool:
    """Apply the setting; returns whether the registry now matches the request."""
    if not is_supported():
        log.info("autostart ignored: needs a packaged Windows build (frozen=%s)", is_frozen())
        return False
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE
        ) as key:
            if enabled:
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, launch_command())
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
        log.info("autostart %s for %s", "enabled" if enabled else "disabled", APP_NAME)
        return is_enabled() == enabled
    except OSError:
        log.exception("failed to update the autostart registry key")
        return False
