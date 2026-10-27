#!/usr/bin/env python3
"""
wmi_event.py  [EXECUTION VERSION]
==================================
WMI Persistent Event Consumer — langsung eksekusi, tanpa CLI parsing.

Behaviour:
  1. Membuat __EventFilter (trigger: process start)
  2. Membuat CommandLineEventConsumer (aksi)
  3. Membuat __FilterToConsumerBinding
  4. (opsional) Verifikasi trigger dengan spawn process uji
  5. Auto-cleanup bila CLEANUP_ON_EXIT = True

Konfigurasi diubah lewat konstanta di blok CONFIG di bawah.

Requires (jalankan sebagai Administrator):
    pip install WMI pywin32

Jalankan:
    python wmi_event.py
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

# =========================================================================
# CONFIG — ubah di sini
# =========================================================================
SUBSCRIPTION_NAME = "WmiEventDemo"        # nama unik (auto-sanitasi)
TRIGGER_PROCESS   = "notepad.exe"         # proses pemicu
TRIGGER_COMMAND   = ""                     # "" = default: tulis marker ke TEMP
POLL_INTERVAL_SEC = 5                      # WITHIN <n> detik
SPAWN_TEST        = True                   # spawn TRIGGER_PROCESS utk uji trigger
SPAWN_TEST_WAIT   = 6                      # detik tunggu sebelum cek marker
CLEANUP_ON_EXIT   = False                  # True = hapus setelah selesai
VERBOSE           = True                   # log level
# =========================================================================


# --- Guard ---------------------------------------------------------------
if os.name != "nt":
    sys.stderr.write("[!] Windows-only.\n")
    sys.exit(1)

try:
    import pythoncom      # type: ignore
    import wmi            # type: ignore
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "[!] Dependency hilang: pip install WMI pywin32\n"
        f"    Detail: {exc}\n"
    )
    sys.exit(1)


NAMESPACE = r"root\subscription"
LOG = logging.getLogger("wmi_event")


# --- Helper --------------------------------------------------------------
def _com_init() -> None:
    pythoncom.CoInitialize()


def _com_uninit() -> None:
    try:
        pythoncom.CoUninitialize()
    except Exception:
        pass


def _connect() -> "wmi.WMI":
    try:
        return wmi.WMI(namespace=NAMESPACE)
    except Exception as exc:
        LOG.error("Koneksi ke %s gagal: %s", NAMESPACE, exc)
        LOG.error("Pastikan terminal berjalan sebagai Administrator.")
        raise


def _sanitize(name: str) -> str:
    safe = "".join(c for c in name if c.isalnum() or c in "_-") or "WmiMon"
    return safe


def _default_command(name: str) -> str:
    marker = os.path.join(
        os.environ.get("TEMP", r"C:\Windows\Temp"),
        f"wmi_event_{name}.log",
    )
    return f'cmd.exe /c echo Triggered %DATE% %TIME% >> "{marker}"'


def _marker_path(name: str) -> str:
    return os.path.join(
        os.environ.get("TEMP", r"C:\Windows\Temp"),
        f"wmi_event_{name}.log",
    )


@dataclass(frozen=True)
class Names:
    base: str
    filter: str
    consumer: str
    binding: str

    @classmethod
    def build(cls, base: str) -> "Names":
        b = _sanitize(base)
        return cls(b, f"{b}_Filter", f"{b}_Consumer", f"{b}_Binding")


# --- Step 1: Event Filter -----------------------------------------------
def create_filter(c: "wmi.WMI", n: Names, process: str, poll: int) -> None:
    query = (
        "SELECT * FROM __InstanceCreationEvent WITHIN {poll} "
        "WHERE TargetInstance ISA 'Win32_Process' "
        "AND TargetInstance.Name = '{proc}'"
    ).format(poll=poll, proc=process.replace("'", "\\'"))

    existing = c.__EventFilter(Name=n.filter)
    if existing:
        f = existing[0]
        if f.Query != query or f.EventNamespace != r"root\cimv2":
            f.Query = query
            f.EventNamespace = r"root\cimv2"
            f.Put_()
            LOG.info("[+] Filter diperbarui: %s", n.filter)
        else:
            LOG.info("[=] Filter sudah sesuai: %s", n.filter)
        return

    c.__EventFilter.new(
        Name=n.filter,
        EventNamespace=r"root\cimv2",
        QueryLanguage="WQL",
        Query=query,
    )
    LOG.info("[+] Filter dibuat: %s", n.filter)


# --- Step 2: Consumer ----------------------------------------------------
def create_consumer(c: "wmi.WMI", n: Names, command: str) -> None:
    existing = c.CommandLineEventConsumer(Name=n.consumer)
    if existing:
        cons = existing[0]
        if cons.CommandLineTemplate != command:
            cons.CommandLineTemplate = command
            cons.Put_()
            LOG.info("[+] Consumer diperbarui: %s", n.consumer)
        else:
            LOG.info("[=] Consumer sudah sesuai: %s", n.consumer)
        return

    c.CommandLineEventConsumer.new(
        Name=n.consumer,
        CommandLineTemplate=command,
        ShowWindowCommand=0,
        KillTimeout=0,
    )
    LOG.info("[+] Consumer dibuat: %s", n.consumer)


# --- Step 3: Binding -----------------------------------------------------
def create_binding(c: "wmi.WMI", n: Names) -> None:
    for b in c.__FilterToConsumerBinding():
        filt = getattr(b, "Filter", "") or ""
        cons = getattr(b, "Consumer", "") or ""
        if n.filter in filt and n.consumer in cons:
            LOG.info("[=] Binding sudah ada")
            return

    c.__FilterToConsumerBinding.new(
        Filter=f"__EventFilter.Name='{n.filter}'",
        Consumer=f"CommandLineEventConsumer.Name='{n.consumer}'",
        Creator="wmi_event.py",
    )
    LOG.info("[+] Binding dibuat: %s", n.binding)


# --- Step 4: Verify ------------------------------------------------------
def verify_trigger(n: Names, process: str, wait: int) -> bool:
    marker = _marker_path(n.base)
    if os.path.exists(marker):
        try:
            os.remove(marker)
        except OSError:
            pass

    LOG.info("[*] Spawn test: %s", process)
    try:
        proc = subprocess.Popen(
            [process],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        LOG.warning("[!] Executable tidak ditemukan: %s", process)
        return False
    except Exception as exc:
        LOG.warning("[!] Gagal spawn test: %s", exc)
        return False

    LOG.info("[*] Menunggu trigger (poll=%ss, wait=%ss)...",
             POLL_INTERVAL_SEC, wait)
    triggered = False
    for _ in range(wait):
        time.sleep(1)
        if os.path.exists(marker):
            triggered = True
            break

    # bereskan proses uji
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        pass

    if triggered:
        LOG.info("[✓] TRIGGER BERHASIL — marker: %s", marker)
    else:
        LOG.warning("[✗] Trigger tidak terdeteksi dalam %ss", wait)
    return triggered


# --- Step 5: Cleanup -----------------------------------------------------
def cleanup(n: Names) -> int:
    c = _connect()
    removed = 0

    for b in list(c.__FilterToConsumerBinding()):
        filt = getattr(b, "Filter", "") or ""
        cons = getattr(b, "Consumer", "") or ""
        if n.filter in filt or n.consumer in cons:
            b.Delete_()
            removed += 1
            LOG.info("[-] Binding dihapus")

    for cons in list(c.CommandLineEventConsumer(Name=n.consumer)):
        cons.Delete_()
        removed += 1
        LOG.info("[-] Consumer dihapus")

    for f in list(c.__EventFilter(Name=n.filter)):
        f.Delete_()
        removed += 1
        LOG.info("[-] Filter dihapus")

    return removed


# --- Main ---------------------------------------------------------------
def main() -> int:
    logging.basicConfig(
        level=logging.DEBUG if VERBOSE else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    n = Names.build(SUBSCRIPTION_NAME)
    command = TRIGGER_COMMAND.strip() or _default_command(n.base)
    poll = max(1, int(POLL_INTERVAL_SEC))

    LOG.info("=== WMI Persistent Subscription Executor ===")
    LOG.info("Nama     : %s", n.base)
    LOG.info("Trigger  : process = %s", TRIGGER_PROCESS)
    LOG.info("Command  : %s", command)
    LOG.info("Poll     : %ss", poll)
    LOG.info("============================================")

    _com_init()
    rc = 0
    try:
        c = _connect()
        create_filter(c, n, TRIGGER_PROCESS, poll)
        create_consumer(c, n, command)
        create_binding(c, n)

        if SPAWN_TEST:
            verify_trigger(n, TRIGGER_PROCESS, SPAWN_TEST_WAIT)

        if CLEANUP_ON_EXIT:
            removed = cleanup(n)
            LOG.info("Cleanup: %d objek dihapus", removed)

        LOG.info("[DONE] Subscription '%s' siap.", n.base)
    except PermissionError:
        LOG.error("Akses ditolak. Jalankan sebagai Administrator.")
        rc = 2
    except Exception as exc:
        LOG.error("Fatal: %s", exc, exc_info=VERBOSE)
        rc = 1
    finally:
        _com_uninit()

    return rc


if __name__ == "__main__":
    sys.exit(main())