"""Privilege detection and requirement checks (best-effort, cross-platform)."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Tuple

_LINUX_CAP_NAMES = ("cap_net_raw", "cap_net_admin", "cap_net_bind_service")


def _linux_has_caps() -> Tuple[bool, str]:
    capsh = shutil.which("capsh")
    if not capsh:
        try:
            return (os.geteuid() == 0, "euid=0" if os.geteuid() == 0 else "no capsh, non-root")
        except AttributeError:
            return (False, "cannot determine capabilities")
    try:
        import subprocess
        out = subprocess.check_output([capsh, "--print"], text=True, stderr=subprocess.DEVNULL)
        if os.geteuid() == 0:
            return True, "running as root"
        for name in _LINUX_CAP_NAMES:
            if f"=cap" not in out and f"cap_" in out:
                if any(f"cap_net_raw" in line and "=ep" in line for line in out.splitlines()):
                    return True, "cap_net_raw+ep present"
                # broad +ep set that includes net_raw
                if any(name in line and ("+ep" in line or "=ep" in line or "=eip" in line)
                       for line in out.splitlines()):
                    return True, f"{name} present (+ep/eip)"
        return False, "no CAP_NET_RAW"
    except Exception as exc:  # pragma: no cover - environment dependent
        return (os.geteuid() == 0, f"capsh unavailable: {exc}")


def _windows_admin() -> Tuple[bool, str]:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin()), "Windows admin check"
    except Exception:
        return False, "cannot check Windows admin status"


def do_have_raw_sockets() -> Tuple[bool, str]:
    """Return (have_raw_socket_capability, human_detail)."""
    system = platform.system()
    if system == "Linux":
        return _linux_has_caps()
    if system in ("Windows", "Darwin"):
        ok, detail = _windows_admin() if system == "Windows" else (os.geteuid() == 0, "macOS admin")
        return (ok, detail) if system == "Windows" else (ok, detail)
    return (False, "unsupported platform")


def require_elevated(reason: str) -> None:
    """Fail fast with a clear message if the process lacks required privilege."""
    ok, detail = do_have_raw_sockets()
    if not ok:
        raise PermissionError(
            f"This operation requires elevated privilege ({reason}). "
            f"Detected: {detail}. On Linux, run with root or grant CAP_NET_RAW; "
            "on Windows/macOS run as administrator. Do NOT run your other "
            "daily work as root as a workaround."
        )


def am_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def platform_label() -> str:
    return platform.platform()


def is_windows() -> bool:
    return sys.platform.startswith("win")