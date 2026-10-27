#!/usr/bin/env python3
"""
test_network.py - High-performance, asynchronous network diagnostic utility.
"""

import asyncio
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("TestNetwork")

@dataclass(frozen=True)
class TargetEndpoint:
    host: str
    port: int
    timeout: float = 3.0

@dataclass
class TestResult:
    host: str
    port: int
    success: bool
    latency_ms: float | None = None
    error_message: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

async def probe_endpoint(target: TargetEndpoint) -> TestResult:
    """Asynchronously probes a TCP endpoint and measures connection latency."""
    loop = asyncio.get_running_loop()
    start_time = loop.time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, target.port),
            timeout=target.timeout
        )
        latency = (loop.time() - start_time) * 1000.0
        writer.close()
        await writer.wait_closed()
        return TestResult(
            host=target.host,
            port=target.port,
            success=True,
            latency_ms=round(latency, 2)
        )
    except asyncio.TimeoutError:
        return TestResult(
            host=target.host,
            port=target.port,
            success=False,
            error_message="Connection timed out"
        )
    except OSError as e:
        return TestResult(
            host=target.host,
            port=target.port,
            success=False,
            error_message=str(e)
        )

async def run_diagnostics(targets: Sequence[TargetEndpoint]) -> list[TestResult]:
    """Executes concurrent probes across all specified target endpoints."""
    logger.info(f"Starting network diagnostics for {len(targets)} targets...")
    tasks = [probe_endpoint(target) for target in targets]
    results = await asyncio.gather(*tasks)
    return list(results)

def main() -> None:
    # Daftar endpoint target untuk diuji
    targets = [
        TargetEndpoint(host="1.1.1.1", port=53),
        TargetEndpoint(host="8.8.8.8", port=53),
        TargetEndpoint(host="github.com", port=443),
        TargetEndpoint(host="example.com", port=80),
    ]

    results = asyncio.run(run_diagnostics(targets))

    logger.info("--- Diagnostic Results Summary ---")
    for res in results:
        if res.success:
            logger.info(f"[SUCCESS] {res.host}:{res.port} | Latency: {res.latency_ms} ms")
        else:
            logger.warning(f"[FAILED]  {res.host}:{res.port} | Error: {res.error_message}")

if __name__ == "__main__":
    main()
