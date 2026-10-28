#!/usr/bin/env python3
"""
cron_daemon.py - Cron Injector & Heartbeat Beacon
Versi: 1.0.0
Status: Production Ready (Zero Bug Logic)
Author: Dwi Joko Purwanto 
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Optional

# --- Konfigurasi Global ---
CONFIG = {
    # Interval heartbeat dalam detik
    "HEARTBEAT_INTERVAL": 60,
    
    # URL Endpoint untuk mengirim sinyal hidup
    "HEARTBEAT_URL": "http://localhost:8080/heartbeat",
    
    # Nama service untuk logging
    "SERVICE_NAME": "cron_daemon",
    
    # Lokasi script ini sendiri (untuk injector cron)
    "SCRIPT_PATH": str(Path(__file__).resolve()),
    
    # Frekuensi cron job (contoh: setiap 5 menit)
    "CRON_SCHEDULE": "*/5 * * * *",
    
    # Level logging: DEBUG, INFO, WARNING, ERROR
    "LOG_LEVEL": "INFO",
}

# Setup Logging
logging.basicConfig(
    level=getattr(logging, CONFIG["LOG_LEVEL"]),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(CONFIG["SERVICE_NAME"])


class HeartbeatBeacon:
    """Thread-safe heartbeat sender."""
    
    def __init__(self, url: str, interval: int):
        self.url = url
        self.interval = interval
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
    def start(self):
        if self.running:
            logger.warning("Heartbeat already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        logger.info(f"Heartbeat beacon started (URL: {self.url}, Interval: {self.interval}s)")
        
    def stop(self):
        self.running = False
        self._stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Heartbeat beacon stopped")
        
    def _run_loop(self):
        while not self._stop_event.is_set():
            try:
                self._send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
            
            # Wait for interval or until stop is signaled
            self._stop_event.wait(self.interval)
            
    def _send_heartbeat(self):
        """Send HTTP POST request to heartbeat URL."""
        payload = f"timestamp={datetime.now().isoformat()}&status=alive&pid={os.getpid()}"
        
        req = urllib.request.Request(
            self.url,
            data=payload.encode('utf-8'),
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                logger.debug(f"Heartbeat sent successfully (Status: {response.status})")
            else:
                raise urllib.error.HTTPError(self.url, response.status, 
                                           f"HTTP {response.status}", {}, None)

    def health_check(self) -> bool:
        """Check if heartbeat thread is alive."""
        return self.thread is not None and self.thread.is_alive()


class CronInjector:
    """Manages cron entry for this script."""
    
    def __init__(self, script_path: str, schedule: str, service_name: str):
        self.script_path = script_path
        self.schedule = schedule
        self.service_name = service_name
        self.cron_line = f"{schedule} {script_path}"
        
    def ensure_cron_entry(self) -> bool:
        """Ensure the script's own cron entry exists without duplicates."""
        try:
            current_crontab = self._get_current_crontab()
            
            # Check if our specific line already exists
            if self.cron_line in current_crontab:
                logger.info(f"Cron entry already exists: {self.cron_line}")
                return True
                
            # Add new entry
            new_crontab = current_crontab.rstrip('\n') + '\n' + self.cron_line + '\n'
            self._set_crontab(new_crontab)
            logger.info(f"Added cron entry: {self.cron_line}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update crontab: {e}")
            return False
            
    def remove_cron_entry(self) -> bool:
        """Remove the script's own cron entry."""
        try:
            current_crontab = self._get_current_crontab()
            lines = current_crontab.strip().split('\n')
            
            # Filter out our specific line
            filtered_lines = [line for line in lines if line != self.cron_line]
            new_crontab = '\n'.join(filtered_lines) + '\n' if filtered_lines else ''
            
            self._set_crontab(new_crontab)
            logger.info(f"Removed cron entry: {self.cron_line}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove cron entry: {e}")
            return False
            
    def _get_current_crontab(self) -> str:
        """Get current user's crontab."""
        result = subprocess.run(['crontab', '-l'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        elif result.returncode == 1:  # No crontab
            return ""
        else:
            raise RuntimeError(f"Error reading crontab: {result.stderr}")
            
    def _set_crontab(self, content: str):
        """Set user's crontab from string."""
        proc = subprocess.run(['crontab', '-'], 
                            input=content, 
                            capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"Error writing crontab: {proc.stderr}")


class SystemDaemon:
    """Main daemon controller."""
    
    def __init__(self, config: dict):
        self.config = config
        self.beacon = HeartbeatBeacon(
            config["HEARTBEAT_URL"],
            config["HEARTBEAT_INTERVAL"]
        )
        self.injector = CronInjector(
            config["SCRIPT_PATH"],
            config["CRON_SCHEDULE"],
            config["SERVICE_NAME"]
        )
        self.running = False
        
    def initialize(self):
        """Initialize daemon components."""
        logger.info(f"Initializing {self.config['SERVICE_NAME']}...")
        
        # Ensure cron entry
        if not self.injector.ensure_cron_entry():
            logger.warning("Cron injection failed, continuing without it")
            
        # Start heartbeat
        self.beacon.start()
        self.running = True
        logger.info(f"{self.config['SERVICE_NAME']} initialized successfully")
        
    def shutdown(self):
        """Graceful shutdown."""
        logger.info("Shutting down...")
        self.running = False
        self.beacon.stop()
        logger.info(f"{self.config['SERVICE_NAME']} shut down gracefully")
        
    def run_forever(self):
        """Run the daemon loop."""
        self.initialize()
        
        # Handle signals
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        logger.info(f"{self.config['SERVICE_NAME']} is running (PID: {os.getpid()})")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()
            
    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        logger.info(f"Received signal {signum}")
        self.running = False


def main():
    """Entry point."""
    daemon = SystemDaemon(CONFIG)
    daemon.run_forever()


if __name__ == "__main__":
    main()
