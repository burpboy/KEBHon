"""
name=registry_hijack.py

Windows Registry Run/RunOnce & COM Object Hijacking Stubs

⚠️ EDUCATIONAL / AUTHORIZED TESTING ONLY ⚠️

This file demonstrates the structure of registry-based persistence
techniques for defensive research, EDR testing, and lab environments.
It intentionally does NOT contain real payloads or evasion logic.
Unauthorized use against systems you don't own is illegal.

Requires: Windows, Python 3.8+, admin (for HKLM), pywin32 optional.
"""

from __future__ import annotations

import os
import sys
import json
import logging
import platform
import argparse
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

try:
    import winreg
except ImportError:  # Non-Windows import guard
    winreg = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("registry_hijack")


# ---------------------------------------------------------------------------
# Safety guard
# ---------------------------------------------------------------------------

class SafetyError(RuntimeError):
    """Raised when an operation is blocked by the safety guard."""
    pass

def require_windows() -> None:
    if winreg is None or platform.system() != "Windows":
        raise SafetyError("This module only runs on Windows with winreg available.")

def require_authorization(confirm_token: str) -> None:
    """
    Mandatory confirmation gate. Caller must pass the exact token
    'I_HAVE_AUTHORIZATION' to proceed with write operations.
    """
    if confirm_token != "I_HAVE_AUTHORIZATION":
        raise SafetyError(
            "Refusing to write registry keys without explicit authorization token."
        )


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RunEntry:
    hive: int
    path: str
    name: str
    value: str

    def describe(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class COMHijackSpec:
    clsid: str                       # e.g. "{00000000-0000-0000-0000-000000000000}"
    hive: int = winreg.HKEY_CURRENT_USER if winreg else 0
    subkey: str = r"Software\Classes\CLSID"
    inproc_server: Optional[str] = None   # path to a DLL (lab-only)
    local_server: Optional[str] = None    # path to an EXE (lab-only)


# ---------------------------------------------------------------------------
# Run / RunOnce operations
# ---------------------------------------------------------------------------

RUN_KEYS: List[str] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

class RunKeyManager:
    """Read/write helpers for Windows Run and RunOnce keys."""
    def __init__(self, hive: int) -> None:
        self.hive = hive

    def list_entries(self) -> List[RunEntry]:
        entries = []
        require_windows()
        for path in RUN_KEYS:
            try:
                with winreg.OpenKey(self.hive, path, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            entries.append(RunEntry(hive=self.hive, path=path, name=name, value=str(value)))
                            i += 1
                        except OSError:
                            break
            except OSError:
                continue
        return entries


# ---------------------------------------------------------------------------
# COM hijacking stubs (structure only)
# ---------------------------------------------------------------------------

class COMHijacker:
    """
    Demonstrates the registry layout used by COM hijacking.
    This class does NOT copy binaries or launch anything.
    """
    def __init__(self, spec: COMHijackSpec) -> None:
        self.spec = spec


# ---------------------------------------------------------------------------
# Reporting / audit
# ---------------------------------------------------------------------------

def audit_report() -> Dict[str, Any]:
    require_windows()
    managers = {
        "HKCU": RunKeyManager(winreg.HKEY_CURRENT_USER),
        "HKLM": RunKeyManager(winreg.HKEY_LOCAL_MACHINE),
    }
    report: Dict[str, Any] = {"platform": platform.platform(), "run_keys": {}}
    for label, mgr in managers.items():
        try:
            report["run_keys"][label] = [e.describe() for e in mgr.list_entries()]
        except OSError as exc:
            report["run_keys"][label] = {"error": str(exc)}
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Registry Run/RunOnce & COM hijack stubs (lab only)."
    )
    p.add_subparsers(dest="cmd", required=True)
    return p

def main(argv: Optional[List[str]] = None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)
    return 0

if __name__ == "__main__":
    sys.exit(main())
