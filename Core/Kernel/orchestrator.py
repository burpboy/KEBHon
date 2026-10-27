"""
orchestrator.py
===============
Distributed Asynchronous Mission Controller
Reactor Pattern + AsyncIO

Design goals:
- Zero-bug: defensive programming, exhaustive error handling, fail-fast validation
- Backpressure-aware: bounded queues, semaphore-based concurrency limits
- Graceful shutdown: signal handling, drain, task cancellation
- Observability: structured logging, metrics, health state
- Idempotent task lifecycle with explicit states

Author: (your name)
Python: 3.10+
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Hashable,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGGER = logging.getLogger("orchestrator")


def _configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(stream=sys.stdout)
    fmt = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class OrchestratorError(Exception):
    """Base orchestrator error."""


class TaskValidationError(OrchestratorError):
    """Raised when a task fails validation before dispatch."""


class QueueFullError(OrchestratorError):
    """Raised when enqueueing would exceed capacity (non-blocking mode)."""


class ShutdownInProgress(OrchestratorError):
    """Raised when new work is submitted during shutdown."""


# ---------------------------------------------------------------------------
# Task model
# ---------------------------------------------------------------------------
class TaskState(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Handler signature: async callable receiving payload -> returns arbitrary result
TaskHandler = Callable[[Any], Awaitable[Any]]
Validator = Callable[[Any], bool]


@dataclass(slots=True)
class MissionTask:
    """A single unit of work dispatched to a handler."""

    task_id: str
    kind: str
    payload: Any
    handler: TaskHandler
    max_retries: int = 0
    timeout: Optional[float] = None
    enqueued_at: float = field(default_factory=time.monotonic)

    # Mutable runtime state
    state: TaskState = field(default=TaskState.PENDING, init=False)
    attempts: int = field(default=0, init=False)
    started_at: Optional[float] = field(default=None, init=False)
    finished_at: Optional[float] = field(default=None, init=False)
    result: Any = field(default=None, init=False)
    error: Optional[BaseException] = field(default=None, init=False)
    future: Optional[asyncio.Future[Any]] = field(default=None, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, str) or not self.task_id:
            raise TaskValidationError("task_id must be a non-empty string")
        if not isinstance(self.kind, str) or not self.kind:
            raise TaskValidationError("kind must be a non-empty string")
        if not callable(self.handler):
            raise TaskValidationError("handler must be callable")
        if self.max_retries < 0:
            raise TaskValidationError("max_retries must be >= 0")
        if self.timeout is not None and self.timeout <= 0:
            raise TaskValidationError("timeout must be > 0 or None")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class Metrics:
    enqueued: int = 0
    started: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    rejected: int = 0
    retries: int = 0

    def snapshot(self) -> Dict[str, int]:
        return {
            "enqueued": self.enqueued,
            "started": self.started,
            "completed": self.completed,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "rejected": self.rejected,
            "retries": self.retries,
        }


# ---------------------------------------------------------------------------
# Dispatcher protocol (pluggable routing)
# ---------------------------------------------------------------------------
class Dispatcher(Protocol):
    def resolve(self, task: MissionTask) -> MissionTask:
        """Return the task to execute (possibly with modified handler)."""
        ...


class KindRouter:
    """Simple dispatcher that routes by `kind` to a registry of handlers."""

    def __init__(self, registry: Dict[str, TaskHandler]) -> None:
        self._registry: Dict[str, TaskHandler] = dict(registry)

    def register(self, kind: str, handler: TaskHandler) -> None:
        if not kind:
            raise TaskValidationError("kind must be non-empty")
        if not callable(handler):
            raise TaskValidationError("handler must be callable")
        self._registry[kind] = handler

    def resolve(self, task: MissionTask) -> MissionTask:
        handler = self._registry.get(task.kind)
        if handler is None:
            raise TaskValidationError(
                f"no handler registered for kind={task.kind!r}"
            )
        task.handler = handler
        return task


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
class Orchestrator:
    """
    Distributed asynchronous mission controller.

    Lifecycle:
        orch = Orchestrator(...)
        await orch.start()
        fut = await orch.submit(task)      # non-blocking; returns future
        await orch.run_until_idle()
        await orch.stop()
    """

    def __init__(
        self,
        dispatcher: Dispatcher,
        *,
        workers: int = 8,
        queue_size: int = 1024,
        name: str = "orchestrator",
        drain_timeout: float = 30.0,
        task_retry_backoff: float = 0.25,
    ) -> None:
        if workers <= 0:
            raise ValueError("workers must be > 0")
        if queue_size <= 0:
            raise ValueError("queue_size must be > 0")
        if drain_timeout <= 0:
            raise ValueError("drain_timeout must be > 0")
        if task_retry_backoff < 0:
            raise ValueError("task_retry_backoff must be >= 0")

        self._name = name
        self._dispatcher = dispatcher
        self._workers = workers
        self._queue: asyncio.Queue[MissionTask] = asyncio.Queue(maxsize=queue_size)
        self._queue_size = queue_size
        self._drain_timeout = drain_timeout
        self._backoff = task_retry_backoff

        self._metrics = Metrics()
        self._running = False
        self._stopping = False
        self._worker_tasks: list[asyncio.Task[None]] = []
        self._active: set[asyncio.Task[Any]] = set()
        self._lifecycle_lock = asyncio.Lock()

    # -- Properties ---------------------------------------------------------
    @property
    def metrics(self) -> Dict[str, int]:
        return self._metrics.snapshot()

    @property
    def is_running(self) -> bool:
        return self._running and not self._stopping

    def _queue_size_now(self) -> int:
        return self._queue.qsize()

    # -- Lifecycle ----------------------------------------------------------
    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._running:
                raise OrchestratorError("orchestrator already running")
            if self._stopping:
                raise OrchestratorError("orchestrator is stopping; cannot restart")
            self._running = True
            self._stopping = False
            self._worker_tasks = [
                asyncio.create_task(self._worker(f"worker-{i}"), name=f"{self._name}-worker-{i}")
                for i in range(self._workers)
            ]
            LOGGER.info(
                "%s started: workers=%d queue_size=%d",
                self._name, self._workers, self._queue_size,
            )

    async def stop(self, *, drain: bool = True) -> None:
        async with self._lifecycle_lock:
            if not self._running:
                return
            self._stopping = True
            LOGGER.info("%s stopping (drain=%s)", self._name, drain)

        try:
            if drain:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._drain(), timeout=self._drain_timeout)

            # Signal sentinels
            for _ in self._worker_tasks:
                with contextlib.suppress(asyncio.QueueFull):
                    self._queue.put_nowait(None)  # type: ignore[arg-type]

            # Cancel workers that don't exit in time
            if self._worker_tasks:
                done, pending = await asyncio.wait(
                    self._worker_tasks, timeout=5.0
                )
                for t in pending:
                    t.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

            # Cancel stragglers
            for t in list(self._active):
                t.cancel()
            if self._active:
                await asyncio.gather(*self._active, return_exceptions=True)
                self._active.clear()

        finally:
            self._running = False
            self._worker_tasks.clear()
            LOGGER.info(
                "%s stopped: metrics=%s", self._name, self._metrics.snapshot()
            )

    async def _drain(self) -> None:
        """Wait until the queue is empty (bounded)."""
        while not self._queue.empty():
            await asyncio.sleep(0.05)
        # Also wait for in-flight tasks
        while self._active:
            await asyncio.sleep(0.05)

    async def run_until_idle(self) -> None:
        """Block until queue is empty and no active tasks. Safe helper."""
        while not self._queue.empty() or self._active:
            await asyncio.sleep(0.02)

    # -- Submission ---------------------------------------------------------
    async def submit(self, task: MissionTask, *, wait: bool = True) -> asyncio.Future[Any]:
        """
        Enqueue a mission task.

        - wait=True  : await slot (backpressure) — preferred
        - wait=False : raise QueueFullError if full

        Returns a future resolving to the task's result.
        Raises ShutdownInProgress if orchestrator is stopping.
        """
        if not isinstance(task, MissionTask):
            raise TaskValidationError("submit() requires a MissionTask")
        if self._stopping or not self._running:
            raise ShutdownInProgress(
                f"{self._name} not accepting new work "
                f"(running={self._running}, stopping={self._stopping})"
            )
        if not task.task_id:
            task.task_id = str(uuid.uuid4())

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        fut.add_done_callback(self._consume_future_exception)
        task.future = fut

        # Resolve handler up front (fail fast on bad kind)
        try:
            self._dispatcher.resolve(task)
        except Exception as exc:
            self._metrics.rejected += 1
            raise TaskValidationError(str(exc)) from exc

        try:
            if wait:
                await self._queue.put(task)
            else:
                self._queue.put_nowait(task)
        except asyncio.QueueFull as exc:
            self._metrics.rejected += 1
            raise QueueFullError(
                f"queue full (size={self._queue_size})"
            ) from exc

        self._metrics.enqueued += 1
        LOGGER.debug(
            "enqueued task=%s kind=%s qsize=%d",
            task.task_id, task.kind, self._queue_size_now(),
        )
        return fut

    @staticmethod
    def _consume_future_exception(fut: asyncio.Future[Any]) -> None:
        """Prevent 'Future exception was never retrieved' warnings."""
        if fut.cancelled():
            return
        exc = fut.exception()
        if exc is not None:
            LOGGER.debug("task future completed with exception: %r", exc)

    # -- Worker loop --------------------------------------------------------
    async def _worker(self, worker_name: str) -> None:
        LOGGER.debug("%s starting", worker_name)
        try:
            while True:
                try:
                    task = await self._queue.get()
                except asyncio.CancelledError:
                    raise
                except Exception:  # pragma: no cover - defensive
                    LOGGER.exception("%s queue.get failed", worker_name)
                    continue

                try:
                    if task is None:  # sentinel
                        return
                    await self._run_task(task, worker_name)
                except asyncio.CancelledError:
                    raise
                except Exception:  # pragma: no cover - defensive
                    LOGGER.exception(
                        "%s unhandled error processing task", worker_name
                    )
                finally:
                    with contextlib.suppress(ValueError):
                        self._queue.task_done()
        except asyncio.CancelledError:
            LOGGER.debug("%s cancelled", worker_name)
            raise
        finally:
            LOGGER.debug("%s exited", worker_name)

    async def _run_task(self, task: MissionTask, worker_name: str) -> None:
        if task.state is not TaskState.PENDING:
            LOGGER.warning(
                "%s skipping task %s in state %s", worker_name, task.task_id, task.state
            )
            return

        task.attempts += 1
        task.state = TaskState.RUNNING
        task.started_at = time.monotonic()
        self._metrics.started += 1

        exec_task: asyncio.Task[Any] = asyncio.create_task(
            self._invoke(task), name=f"{self._name}-task-{task.task_id}"
        )
        self._active.add(exec_task)
        try:
            result = await exec_task
        except asyncio.CancelledError:
            task.state = TaskState.CANCELLED
            task.finished_at = time.monotonic()
            self._metrics.cancelled += 1
            self._resolve_future(task, error=asyncio.CancelledError())
            raise
        except Exception as exc:
            # Retry logic
            if task.attempts <= task.max_retries and not self._stopping:
                delay = self._backoff * (2 ** (task.attempts - 1))
                LOGGER.warning(
                    "task %s failed (attempt %d/%d): %r; retry in %.2fs",
                    task.task_id, task.attempts, task.max_retries + 1, exc, delay,
                )
                task.state = TaskState.PENDING
                task.error = exc
                self._metrics.retries += 1
                await asyncio.sleep(delay)
                # Re-enqueue at tail (bounded)
                try:
                    await self._queue.put(task)
                except asyncio.QueueFull:
                    LOGGER.error(
                        "cannot requeue task %s: queue full", task.task_id
                    )
                    self._finalize_failure(task, exc)
                return

            self._finalize_failure(task, exc)
            return
        else:
            task.state = TaskState.COMPLETED
            task.result = result
            task.finished_at = time.monotonic()
            self._metrics.completed += 1
            self._resolve_future(task, result=result)
            LOGGER.debug(
                "task %s completed in %.3fs",
                task.task_id, task.finished_at - (task.started_at or task.finished_at),
            )
        finally:
            self._active.discard(exec_task)

    async def _invoke(self, task: MissionTask) -> Any:
        """Invoke handler with optional timeout."""
        coro = task.handler(task.payload)
        if task.timeout is not None:
            return await asyncio.wait_for(coro, timeout=task.timeout)
        return await coro

    def _finalize_failure(self, task: MissionTask, exc: BaseException) -> None:
        task.state = TaskState.FAILED
        task.error = exc
        task.finished_at = time.monotonic()
        self._metrics.failed += 1
        self._resolve_future(task, error=exc)
        LOGGER.error("task %s failed: %r", task.task_id, exc)

    def _resolve_future(
        self,
        task: MissionTask,
        *,
        result: Any = None,
        error: Optional[BaseException] = None,
    ) -> None:
        fut = task.future
        if fut is None or fut.done():
            return
        if error is not None:
            fut.set_exception(error)
        else:
            fut.set_result(result)


# ---------------------------------------------------------------------------
# Signal handling helper
# ---------------------------------------------------------------------------
def install_signal_handlers(
    loop: asyncio.AbstractEventLoop,
    orch: Orchestrator,
    stop_event: asyncio.Event,
) -> None:
    """Install SIGINT/SIGTERM that trigger graceful shutdown."""

    def _handle(signum: int) -> None:
        LOGGER.info("received signal %d; initiating shutdown", signum)
        if not stop_event.is_set():
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle, sig)
        except (NotImplementedError, RuntimeError):
            # Windows / unsupported
            with contextlib.suppress(ValueError):
                signal.signal(
                    sig, lambda s, _f: _handle(s)  # type: ignore[arg-type]
                )


# ---------------------------------------------------------------------------
# Demo / smoke test
# ---------------------------------------------------------------------------
async def _demo() -> None:
    _configure_logging(logging.INFO)

    async def handle_echo(payload: Any) -> Any:
        await asyncio.sleep(0.05)
        return {"echo": payload}

    async def handle_flaky(payload: Any) -> Any:
        # Succeeds on 2nd attempt (max_retries=2)
        if not payload.get("_retry"):
            payload["_retry"] = True
            raise RuntimeError("transient failure")
        return {"ok": payload}

    async def handle_slow(payload: Any) -> Any:
        await asyncio.sleep(10)
        return "should-not-reach"

    router = KindRouter(
        {
            "echo": handle_echo,
            "flaky": handle_flaky,
            "slow": handle_slow,
        }
    )
    orch = Orchestrator(
        router, workers=4, queue_size=64, name="demo-orch", drain_timeout=5.0
    )
    stop_event = asyncio.Event()
    install_signal_handlers(asyncio.get_running_loop(), orch, stop_event)

    await orch.start()

    futures: list[asyncio.Future[Any]] = []
    for i in range(20):
        futures.append(
            await orch.submit(
                MissionTask(
                    task_id=f"echo-{i}", kind="echo", payload={"i": i}, handler=handle_echo
                )
            )
        )

    futures.append(
        await orch.submit(
            MissionTask(
                task_id="flaky-1",
                kind="flaky",
                payload={},
                handler=handle_flaky,
                max_retries=2,
            )
        )
    )

    futures.append(
        await orch.submit(
            MissionTask(
                task_id="slow-1",
                kind="slow",
                payload={},
                handler=handle_slow,
                timeout=0.5,
            )
        )
    )

    results = await asyncio.gather(*futures, return_exceptions=True)
    ok = sum(1 for r in results if not isinstance(r, BaseException))
    bad = len(results) - ok
    LOGGER.info("results: ok=%d bad=%d metrics=%s", ok, bad, orch.metrics)

    await orch.stop(drain=True)


def main() -> int:
    try:
        asyncio.run(_demo())
    except KeyboardInterrupt:
        LOGGER.info("interrupted by user")
        return 130
    except Exception:
        LOGGER.exception("fatal error")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())