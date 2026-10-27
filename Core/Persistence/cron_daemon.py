#!/usr/bin/env python3
"""
cron_daemon.py
===============
Cron / Systemd Service Daemon Injector & Heartbeat Beacon

A production-grade daemon that:
  1. Injects itself into cron / systemd for persistence.
  2. Emits periodic heartbeats to a configurable beacon sink
     (file, syslog, or HTTP endpoint).
  3. Handles graceful shutdown on SIGTERM / SIGINT.
  4. Uses atomic writes and defensive error handling throughout.

Author : (your name)
License: MIT
Python : >= 3.8
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import errno
import hashlib
import http.client
import json
import logging
import logging.handlers
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "cron_daemon"
APP_VERSION = "1.0.0"
DEFAULT_INTERVAL = 60          # seconds between heartbeats
DEFAULT_CRON_SCHEDULE = "*/5 * * * *"
DEFAULT_SYSTEMD_INTERVAL = "5min"
CRON_MARKER = "# managed-by:cron_daemon"
SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """Runtime configuration for the daemon."""
    interval: int = DEFAULT_INTERVAL
    beacon: str = "file"                       # file | syslog | http | null
    beacon_target: str = ""                    # path / url / none
    log_file: Path = field(
        default_factory=lambda: Path.home() / ".local/share" / APP_NAME / "daemon.log"
    )
    state_file: Path = field(
        default_factory=lambda: Path.home() / ".local/share" / APP_NAME / "state.json"
    )
    pid_file: Path = field(
        default_factory=lambda: Path.home() / ".local/share" / APP_NAME / "daemon.pid"
    )
    once: bool = False                         # run one heartbeat and exit
    verbose: bool = False
    inject_cron: bool = False
    inject_systemd: bool = False
    remove: bool = False
    foreground: bool = True

    def __post_init__(self) -> None:
        # Normalize / expand paths
        self.log_file = Path(os.path.expanduser(str(self.log_file))).resolve()
        self.state_file = Path(os.path.expanduser(str(self.state_file))).resolve()
        self.pid_file = Path(os.path.expanduser(str(self.pid_file))).resolve()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dir(path: Path) -> None:
    """Create a directory (and parents) if it does not exist."""
    path.mkdir(parents=True, exist_ok=True)


def atomic_write(path: Path, data: str) -> None:
    """
    Atomically write *data* to *path* using a temp file + rename.
    Prevents partial writes on crash.
    """
    ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def read_json(path: Path, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read a JSON file, returning *default* on any error."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return dict(default or {})


def pid_alive(pid: int) -> bool:
    """Return True if *pid* refers to a running process owned by us."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(cfg: Config) -> logging.Logger:
    """Configure the root logger with console + rotating file handlers."""
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.DEBUG if cfg.verbose else logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    try:
        ensure_dir(cfg.log_file.parent)
        fh = logging.handlers.RotatingFileHandler(
            cfg.log_file,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError as exc:
        # Fall back to stderr if the log file is not writable
        sys.stderr.write(f"[warn] cannot open log file {cfg.log_file}: {exc}\n")

    sh = logging.StreamHandler(sys.stderr if not cfg.foreground else sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


# ---------------------------------------------------------------------------
# Beacon sinks
# ---------------------------------------------------------------------------

class BeaconSink:
    """Base class for heartbeat sinks."""
    name: str = "base"

    def emit(self, payload: Dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:
        pass


class FileBeacon(BeaconSink):
    name = "file"

    def __init__(self, path: Path) -> None:
        self.path = path
        ensure_dir(self.path.parent)

    def emit(self, payload: Dict[str, Any]) -> None:
        line = json.dumps(payload, separators=(",", ":")) + "\n"
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())


class SyslogBeacon(BeaconSink):
    name = "syslog"

    def __init__(self) -> None:
        import syslog as _syslog  # local import: not available on Windows
        self._syslog = _syslog
        self._syslog.openlog(APP_NAME, self._syslog.LOG_PID, self._syslog.LOG_DAEMON)

    def emit(self, payload: Dict[str, Any]) -> None:
        self._syslog.syslog(
            self._syslog.LOG_INFO,
            json.dumps(payload, separators=(",", ":")),
        )


class HttpBeacon(BeaconSink):
    name = "http"

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"invalid HTTP beacon URL: {url!r}")
        self.url = url
        self.timeout = timeout
        self._parsed = parsed

    def emit(self, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        conn_cls = (
            http.client.HTTPSConnection
            if self._parsed.scheme == "https"
            else http.client.HTTPConnection
        )
        conn = conn_cls(self._parsed.hostname, self._parsed.port, timeout=self.timeout)
        try:
            path = self._parsed.path or "/"
            if self._parsed.query:
                path += "?" + self._parsed.query
            conn.request(
                "POST",
                path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"{APP_NAME}/{APP_VERSION}",
                    "Content-Length": str(len(body)),
                },
            )
            resp = conn.getresponse()
            resp.read()
            if resp.status >= 400:
                raise RuntimeError(f"HTTP beacon returned {resp.status}")
        finally:
            conn.close()


class NullBeacon(BeaconSink):
    name = "null"

    def emit(self, payload: Dict[str, Any]) -> None:
        pass


def build_beacon(cfg: Config) -> BeaconSink:
    """Construct the beacon sink from configuration."""
    kind = (cfg.beacon or "null").lower()
    if kind == "file":
        target = Path(cfg.beacon_target) if cfg.beacon_target else (
            cfg.state_file.parent / "heartbeats.jsonl"
        )
        return FileBeacon(Path(os.path.expanduser(str(target))).resolve())
    if kind == "syslog":
        return SyslogBeacon()
    if kind == "http":
        if not cfg.beacon_target:
            raise ValueError("--beacon=http requires --beacon-target=<url>")
        return HttpBeacon(cfg.beacon_target)
    if kind == "null":
        return NullBeacon()
    raise ValueError(f"unknown beacon type: {kind!r}")


# ---------------------------------------------------------------------------
# Heartbeat engine
# ---------------------------------------------------------------------------

class Heartbeat:
    """Thread-safe heartbeat emitter."""

    def __init__(self, cfg: Config, sink: BeaconSink, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.sink = sink
        self.log = logger
        self.instance_id = self._load_or_create_id()
        self.count = 0
        self._lock = threading.Lock()

    def _load_or_create_id(self) -> str:
        state = read_json(self.cfg.state_file)
        ident = state.get("instance_id")
        if not isinstance(ident, str) or not ident:
            ident = uuid.uuid4().hex
            state["instance_id"] = ident
            state["created_at"] = utc_now_iso()
            with contextlib.suppress(OSError):
                atomic_write(self.cfg.state_file, json.dumps(state, indent=2))
        return ident

    def _payload(self) -> Dict[str, Any]:
        hostname = socket.gethostname()
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "instance_id": self.instance_id,
            "hostname": hostname,
            "pid": os.getpid(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "seq": self.count,
            "timestamp": utc_now_iso(),
            "monotonic": time.monotonic(),
        }

    def beat(self) -> bool:
        """Emit one heartbeat. Returns True on success."""
        with self._lock:
            self.count += 1
            payload = self._payload()
            try:
                self.sink.emit(payload)
                self.log.debug("heartbeat #%d emitted", self.count)
                return True
            except Exception:
                self.log.exception("heartbeat #%d failed", self.count)
                return False

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.sink.close()


# ---------------------------------------------------------------------------
# Service injectors
# ---------------------------------------------------------------------------

class InjectionError(RuntimeError):
    """Raised when a persistence injector fails."""


def _self_argv() -> list[str]:
    """Return a list of args that re-launch this script."""
    return [sys.executable, str(Path(__file__).resolve())]


class CronInjector:
    """Manage an entry in the current user's crontab."""

    def __init__(self, schedule: str = DEFAULT_CRON_SCHEDULE) -> None:
        self.schedule = schedule

    def _crontab_bin(self) -> str:
        bin_path = shutil.which("crontab")
        if not bin_path:
            raise InjectionError("crontab binary not found in PATH")
        return bin_path

    def _current(self) -> str:
        try:
            proc = subprocess.run(
                [self._crontab_bin(), "-l"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise InjectionError(f"cannot read crontab: {exc}") from exc
        # `crontab -l` returns 1 when empty; that's fine
        return proc.stdout or ""

    def install(self) -> None:
        current = self._current()
        lines = [ln for ln in current.splitlines() if CRON_MARKER not in ln]
        cmd = " ".join(_self_argv() + ["--once", "--beacon=null"])
        entry = f"{self.schedule} {cmd} {CRON_MARKER}"
        lines.append(entry)
        new = "\n".join(lines).rstrip() + "\n"
        self._write(new)

    def remove(self) -> None:
        current = self._current()
        lines = [ln for ln in current.splitlines() if CRON_MARKER not in ln]
        new = "\n".join(lines).rstrip()
        if new:
            new += "\n"
        self._write(new)

    def _write(self, content: str) -> None:
        try:
            proc = subprocess.run(
                [self._crontab_bin(), "-"],
                input=content,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise InjectionError(f"cannot write crontab: {exc}") from exc
        if proc.returncode != 0:
            raise InjectionError(
                f"crontab - returned {proc.returncode}: {proc.stderr.strip()}"
            )


class SystemdInjector:
    """Install a user-level systemd unit."""

    UNIT_TEMPLATE = """\
[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=10
WorkingDirectory={workdir}
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"""

    def __init__(self, unit_name: str = f"{APP_NAME}.service") -> None:
        self.unit_name = unit_name
        self.user_unit_dir = Path.home() / ".config" / "systemd" / "user"
        self.unit_path = self.user_unit_dir / self.unit_name

    def install(self) -> None:
        if not shutil.which("systemctl"):
            raise InjectionError("systemctl not found in PATH")
        exec_start = " ".join(_self_argv() + ["--beacon=file", "--foreground"])
        content = self.UNIT_TEMPLATE.format(
            description="cron_daemon heartbeat beacon",
            exec_start=exec_start,
            workdir=str(Path.home()),
        )
        ensure_dir(self.user_unit_dir)
        atomic_write(self.unit_path, content)
        self._systemctl("daemon-reload")
        self._systemctl("enable", "--now", self.unit_name)

    def remove(self) -> None:
        if self.unit_path.exists():
            with contextlib.suppress(Exception):
                self._systemctl("disable", "--now", self.unit_name)
            with contextlib.suppress(OSError):
                self.unit_path.unlink()
            with contextlib.suppress(Exception):
                self._systemctl("daemon-reload")

    def _systemctl(self, *args: str) -> None:
        try:
            proc = subprocess.run(
                ["systemctl", "--user", *args],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise InjectionError(f"systemctl failed: {exc}") from exc
        if proc.returncode != 0:
            raise InjectionError(
                f"systemctl {' '.join(args)} -> {proc.returncode}: "
                f"{proc.stderr.strip()}"
            )


# ---------------------------------------------------------------------------
# Daemon runtime
# ---------------------------------------------------------------------------

class Daemon:
    """Main daemon lifecycle: pid-file, signals, heartbeat loop."""

    def __init__(self, cfg: Config, logger: logging.Logger) -> None:
        self.cfg = cfg
        self.log = logger
        self._stop = threading.Event()
        self._heartbeat: Optional[Heartbeat] = None
        self._pid_written = False

    # ---- pid file ---------------------------------------------------------

    def _acquire_pidfile(self) -> None:
        ensure_dir(self.cfg.pid_file.parent)
        if self.cfg.pid_file.exists():
            try:
                existing = int(self.cfg.pid_file.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                existing = 0
            if existing and pid_alive(existing) and existing != os.getpid():
                raise RuntimeError(
                    f"another instance is already running (pid {existing})"
                )
        atomic_write(self.cfg.pid_file, f"{os.getpid()}\n")
        self._pid_written = True

    def _release_pidfile(self) -> None:
        if not self._pid_written:
            return
        with contextlib.suppress(OSError):
            self.cfg.pid_file.unlink()
        self._pid_written = False

    # ---- signals ----------------------------------------------------------

    def _install_signals(self) -> None:
        for sig in (signal.SIGTERM, signal.SIGINT):
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, self._on_signal)
        if hasattr(signal, "SIGHUP"):
            with contextlib.suppress(ValueError, OSError):
                signal.signal(signal.SIGHUP, self._on_signal)

    def _on_signal(self, signum: int, _frame: Any) -> None:
        self.log.info("received signal %s, shutting down", signum)
        self._stop.set()

    # ---- main loop --------------------------------------------------------

    def run(self) -> int:
        try:
            self._acquire_pidfile()
        except RuntimeError as exc:
            self.log.error("%s", exc)
            return 2

        self._install_signals()
        atexit.register(self._release_pidfile)

        try:
            sink = build_beacon(self.cfg)
        except Exception:
            self.log.exception("failed to build beacon")
            return 3

        self._heartbeat = Heartbeat(self.cfg, sink, self.log)
        self.log.info(
            "starting %s v%s (pid=%d, interval=%ds, beacon=%s)",
            APP_NAME, APP_VERSION, os.getpid(),
            self.cfg.interval, sink.name,
        )

        try:
            if self.cfg.once:
                ok = self._heartbeat.beat()
                return 0 if ok else 1

            next_beat = time.monotonic()
            while not self._stop.is_set():
                now = time.monotonic()
                if now >= next_beat:
                    self._heartbeat.beat()
                    next_beat = now + self.cfg.interval
                # Wait for either stop signal or the next scheduled beat
                wait = max(0.0, next_beat - time.monotonic())
                if self._stop.wait(timeout=min(wait, 1.0)):
                    break
        except Exception:
            self.log.exception("fatal error in daemon loop")
            return 4
        finally:
            if self._heartbeat:
                self._heartbeat.close()
            self._release_pidfile()
            self.log.info("stopped")
        return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Cron/Systemd daemon injector & heartbeat beacon.",
    )
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                   help="heartbeat interval in seconds (default: %(default)s)")
    p.add_argument("--beacon", choices=["file", "syslog", "http", "null"],
                   default="file", help="heartbeat sink type")
    p.add_argument("--beacon-target", default="",
                   help="beacon target (path/url); empty = default")
    p.add_argument("--log-file", default=str(Config().log_file),
                   help="path to the log file")
    p.add_argument("--once", action="store_true",
                   help="emit one heartbeat and exit")
    p.add_argument("--verbose", action="store_true", help="debug logging")
    p.add_argument("--inject-cron", action="store_true",
                   help="install a crontab entry")
    p.add_argument("--inject-systemd", action="store_true",
                   help="install a user systemd unit")
    p.add_argument("--cron-schedule", default=DEFAULT_CRON_SCHEDULE,
                   help="cron expression (default: %(default)s)")
    p.add_argument("--remove", action="store_true",
                   help="remove cron/systemd entries and exit")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.interval <= 0:
        parser.error("--interval must be a positive integer")

    cfg = Config(
        interval=args.interval,
        beacon=args.beacon,
        beacon_target=args.beacon_target,
        log_file=Path(args.log_file),
        once=args.once,
        verbose=args.verbose,
        inject_cron=args.inject_cron,
        inject_systemd=args.inject_systemd,
        remove=args.remove,
    )
    logger = setup_logging(cfg)

    # ---- removal mode -----------------------------------------------------
    if cfg.remove:
        rc = 0
        if shutil.which("crontab"):
            try:
                CronInjector(args.cron_schedule).remove()
                logger.info("crontab entry removed")
            except InjectionError as exc:
                logger.warning("cron removal failed: %s", exc)
                rc = 1
        else:
            logger.info("crontab not available; skipping")
        try:
            SystemdInjector().remove()
            logger.info("systemd unit removed")
        except InjectionError as exc:
            logger.debug("systemd removal skipped: %s", exc)
        return rc

    # ---- injection mode ---------------------------------------------------
    if cfg.inject_cron:
        try:
            CronInjector(args.cron_schedule).install()
            logger.info("crontab entry installed")
        except InjectionError as exc:
            logger.error("cron injection failed: %s", exc)
            return 5
    if cfg.inject_systemd:
        try:
            SystemdInjector().install()
            logger.info("systemd unit installed")
        except InjectionError as exc:
            logger.error("systemd injection failed: %s", exc)
            return 6
    if cfg.inject_cron or cfg.inject_systemd:
        if not (cfg.once or args.beacon == "null"):
            # Do not fall through to long-running mode when only injecting.
            return 0

    # ---- daemon mode ------------------------------------------------------
    daemon = Daemon(cfg, logger)
    try:
        return daemon.run()
    except Exception:
        logger.exception("unhandled exception")
        return 1


if __name__ == "__main__":
    sys.exit(main())