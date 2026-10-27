# thread_pool.py
# Thread/Process Pool Manager with Dynamic Load Balancing
# Python 3.8+ | Zero-dependency (stdlib only)
#
# Features:
#   - Dynamic load balancing (least-loaded worker selection)
#   - Hybrid Thread / Process execution
#   - Per-task cancellation, priorities, bounded queues
#   - Futures with .result() / .cancel() / .done()
#   - Exception propagation & metrics
#   - Idempotent shutdown (context-manager supported)
# License: MIT

from __future__ import annotations

import logging
import os
import queue
import threading
import time
import traceback
import weakref
from concurrent.futures import Future, ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# --------------------------------------------------------------------------- #
# Enums & Data Models
# --------------------------------------------------------------------------- #

class ExecutorType(Enum):
    """Underlying executor strategy for a pool."""
    THREAD = auto()
    PROCESS = auto()


class TaskState(Enum):
    """Lifecycle states for a submitted task."""
    PENDING = auto()
    RUNNING = auto()
    DONE = auto()
    CANCELLED = auto()
    FAILED = auto()


@dataclass(order=True)
class _QueuedTask:
    """Internal task wrapper, ordered by (priority, sequence)."""
    priority: int
    sequence: int
    fn: Callable[..., Any] = field(compare=False)
    args: Tuple[Any, ...] = field(compare=False)
    kwargs: Dict[str, Any] = field(compare=False)
    future: Future = field(compare=False)
    submitted_at: float = field(compare=False, default_factory=time.monotonic)
    state: TaskState = field(compare=False, default=TaskState.PENDING)
    started_at: Optional[float] = field(compare=False, default=None)
    finished_at: Optional[float] = field(compare=False, default=None)
    worker_id: Optional[int] = field(compare=False, default=None)


# --------------------------------------------------------------------------- #
# Pool Metrics
# --------------------------------------------------------------------------- #

@dataclass
class PoolMetrics:
    """Snapshot of a pool's runtime metrics."""
    submitted: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    active: int = 0
    queued: int = 0
    peak_active: int = 0
    peak_queue: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "submitted": self.submitted,
            "completed": self.completed,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "active": self.active,
            "queued": self.queued,
            "peak_active": self.peak_active,
            "peak_queue": self.peak_queue,
        }


# --------------------------------------------------------------------------- #
# Main Pool
# --------------------------------------------------------------------------- #

class DynamicPool:
    """Hybrid thread/process pool with dynamic load balancing."""

    def __init__(
        self,
        max_workers: Optional[int] = None,
        executor_type: ExecutorType = ExecutorType.THREAD,
        *,
        max_queue_size: int = 0,
        name: Optional[str] = None,
        auto_scale: bool = True,
        min_workers: int = 1,
        max_workers_limit: Optional[int] = None,
        process_initializer: Optional[Callable[..., Any]] = None,
        process_initargs: Tuple[Any, ...] = (),
    ) -> None:
        if max_workers is None:
            max_workers = (os.cpu_count() or 4) * (
                5 if executor_type == ExecutorType.THREAD else 1
            )
        if max_workers <= 0:
            raise ValueError("max_workers must be positive")

        self._executor_type = executor_type
        self._max_workers = max_workers
        self._min_workers = max(1, min(min_workers, max_workers))
        self._max_workers_limit = max(self._max_workers, max_workers_limit or self._max_workers)
        self._auto_scale = auto_scale
        self._name = name or f"DynamicPool-{id(self):x}"
        self._max_queue_size = max_queue_size

        self._task_queue: "queue.PriorityQueue[_QueuedTask]" = queue.PriorityQueue(
            maxsize=max_queue_size if max_queue_size > 0 else 0
        )
        self._seq_counter = 0
        self._seq_lock = threading.Lock()

        self._workers: List[Union[ThreadPoolExecutor, ProcessPoolExecutor]] = []
        self._worker_active: List[int] = []
        self._worker_lock = threading.Lock()

        self._shutdown_event = threading.Event()
        self._dispatcher: Optional[threading.Thread] = None
        self._metrics_lock = threading.Lock()
        self._metrics = PoolMetrics()
        self._inflight: "weakref.WeakSet[Future]" = weakref.WeakSet()

        self._proc_initializer = process_initializer
        self._proc_initargs = process_initargs

        self._spawn_workers(self._min_workers)
        self._start_dispatcher()

    # ---------------------------- Public API ---------------------------- #

    def submit(
        self,
        fn: Callable[..., Any],
        *args: Any,
        priority: int = 0,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> Future:
        """Submit a task; returns a Future."""
        self._ensure_running()

        fut: Future = Future()
        with self._seq_lock:
            seq = self._seq_counter
            self._seq_counter += 1

        task = _QueuedTask(
            priority=priority,
            sequence=seq,
            fn=fn,
            args=args,
            kwargs=kwargs,
            future=fut,
        )

        try:
            self._task_queue.put(task, block=True, timeout=timeout)
        except queue.Full:
            with self._metrics_lock:
                self._metrics.cancelled += 1
            fut.cancel()
            raise queue.Full(
                f"[{self._name}] task queue is full (max={self._max_queue_size})"
            )

        with self._metrics_lock:
            self._metrics.submitted += 1
            qsize = self._task_queue.qsize()
            self._metrics.queued = qsize
            if qsize > self._metrics.peak_queue:
                self._metrics.peak_queue = qsize

        self._inflight.add(fut)
        return fut

    def map(
        self,
        fn: Callable[[Any], Any],
        iterable: Iterable[Any],
        *,
        priority: int = 0,
        timeout: Optional[float] = None,
    ) -> List[Future]:
        """Submit fn for each item; returns futures in order."""
        return [
            self.submit(fn, item, priority=priority, timeout=timeout)
            for item in iterable
        ]

    def shutdown(self, wait: bool = True, cancel_pending: bool = True) -> None:
        """Gracefully stop the pool. Idempotent."""
        if self._shutdown_event.is_set():
            if wait and self._dispatcher is not None and self._dispatcher.is_alive():
                self._dispatcher.join()
            return

        self._shutdown_event.set()

        if cancel_pending:
            self._drain_queue(cancel=True)

        try:
            self._task_queue.put_nowait(
                _QueuedTask(
                    priority=1 << 30,
                    sequence=-1,
                    fn=_noop,
                    args=(),
                    kwargs={},
                    future=Future(),
                )
            )
        except queue.Full:
            pass

        if wait and self._dispatcher is not None:
            self._dispatcher.join(timeout=10.0)

        with self._worker_lock:
            workers = list(self._workers)
            self._workers.clear()
            self._worker_active.clear()

        for w in workers:
            try:
                w.shutdown(wait=wait, cancel_futures=cancel_pending)
            except TypeError:
                w.shutdown(wait=wait)

    def __enter__(self) -> "DynamicPool":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.shutdown(wait=True)

    # -------------------------- Introspection --------------------------- #

    @property
    def metrics(self) -> PoolMetrics:
        with self._metrics_lock:
            with self._worker_lock:
                active = sum(self._worker_active)
                return PoolMetrics(
                    submitted=self._metrics.submitted,
                    completed=self._metrics.completed,
                    failed=self._metrics.failed,
                    cancelled=self._metrics.cancelled,
                    active=active,
                    queued=self._task_queue.qsize(),
                    peak_active=self._metrics.peak_active,
                    peak_queue=self._metrics.peak_queue,
                )

    def is_running(self) -> bool:
        return not self._shutdown_event.is_set()

    # ----------------------- Worker management -------------------------- #

    def _spawn_workers(self, count: int) -> None:
        with self._worker_lock:
            for _ in range(count):
                if len(self._workers) >= self._max_workers_limit:
                    break
                if self._executor_type == ExecutorType.THREAD:
                    ex: Union[ThreadPoolExecutor, ProcessPoolExecutor] = ThreadPoolExecutor(
                        max_workers=1, thread_name_prefix=f"{self._name}-w"
                    )
                else:
                    ex = ProcessPoolExecutor(
                        max_workers=1,
                        initializer=self._proc_initializer,
                        initargs=self._proc_initargs,
                    )
                self._workers.append(ex)
                self._worker_active.append(0)

    def _maybe_scale_up(self) -> None:
        if not self._auto_scale:
            return
        with self._worker_lock:
            if len(self._workers) >= self._max_workers_limit:
                return
            if all(a > 0 for a in self._worker_active):
                self._spawn_workers(1)

    def _pick_least_loaded(self) -> int:
        with self._worker_lock:
            return min(range(len(self._workers)), key=lambda i: self._worker_active[i])

    # --------------------------- Dispatcher ----------------------------- #

    def _start_dispatcher(self) -> None:
        self._dispatcher = threading.Thread(
            target=self._dispatch_loop,
            name=f"{self._name}-dispatcher",
            daemon=True,
        )
        self._dispatcher.start()

    def _dispatch_loop(self) -> None:
        while not self._shutdown_event.is_set() or not self._task_queue.empty():
            try:
                task = self._task_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if task.sequence == -1 and task.fn is _noop:
                self._task_queue.task_done()
                continue

            if self._shutdown_event.is_set():
                self._cancel_task(task)
                self._task_queue.task_done()
                continue

            if task.future.cancelled():
                self._record_cancel()
                self._task_queue.task_done()
                continue

            try:
                self._dispatch_task(task)
            except Exception:
                logger.exception("[%s] dispatch failed", self._name)
                task.future.set_exception(traceback.format_exc())
                self._record_failure()
            finally:
                self._task_queue.task_done()

    def _dispatch_task(self, task: _QueuedTask) -> None:
        self._maybe_scale_up()
        idx = self._pick_least_loaded()

        with self._worker_lock:
            if idx >= len(self._workers):
                raise RuntimeError("worker index out of range")
            ex = self._workers[idx]
            self._worker_active[idx] += 1
            self._metrics.active = sum(self._worker_active)
            if self._metrics.active > self._metrics.peak_active:
                self._metrics.peak_active = self._metrics.active

        task.state = TaskState.RUNNING
        task.started_at = time.monotonic()
        task.worker_id = idx

        try:
            inner_fut = ex.submit(task.fn, *task.args, **task.kwargs)
        except Exception:
            self._release_worker(idx)
            raise

        inner_fut.add_done_callback(
            lambda f, _task=task, _idx=idx: self._on_task_done(_task, _idx, f)
        )

    def _on_task_done(self, task: _QueuedTask, worker_idx: int, inner: Future) -> None:
        task.finished_at = time.monotonic()
        try:
            if inner.cancelled():
                task.state = TaskState.CANCELLED
                self._record_cancel()
                if not task.future.done():
                    task.future.cancel()
                return

            exc = inner.exception()
            if exc is not None:
                task.state = TaskState.FAILED
                self._record_failure()
                if not task.future.done():
                    task.future.set_exception(exc)
            else:
                task.state = TaskState.DONE
                self._record_success()
                if not task.future.done():
                    task.future.set_result(inner.result())
        finally:
            self._release_worker(worker_idx)

    def _release_worker(self, idx: int) -> None:
        with self._worker_lock:
            if 0 <= idx < len(self._worker_active):
                self._worker_active[idx] = max(0, self._worker_active[idx] - 1)
            self._metrics.active = sum(self._worker_active)

    # ---------------------- Metrics & queue helpers --------------------- #

    def _record_success(self) -> None:
        with self._metrics_lock:
            self._metrics.completed += 1

    def _record_failure(self) -> None:
        with self._metrics_lock:
            self._metrics.failed += 1

    def _record_cancel(self) -> None:
        with self._metrics_lock:
            self._metrics.cancelled += 1

    def _cancel_task(self, task: _QueuedTask) -> None:
        task.state = TaskState.CANCELLED
        if not task.future.done():
            task.future.cancel()
        self._record_cancel()

    def _drain_queue(self, cancel: bool = True) -> None:
        while True:
            try:
                t = self._task_queue.get_nowait()
            except queue.Empty:
                break
            if cancel:
                self._cancel_task(t)
            self._task_queue.task_done()

    def _ensure_running(self) -> None:
        if self._shutdown_event.is_set():
            raise RuntimeError(f"[{self._name}] pool is shut down")


# --------------------------------------------------------------------------- #
# Module-level helpers
# --------------------------------------------------------------------------- #

def _noop(*_a: Any, **_k: Any) -> None:
    """No-op used as shutdown sentinel."""
    return None


# --------------------------------------------------------------------------- #
# Convenience factory
# --------------------------------------------------------------------------- #

def create_pool(
    executor_type: Union[str, ExecutorType] = "thread",
    max_workers: Optional[int] = None,
    **kwargs: Any,
) -> DynamicPool:
    """Convenience constructor. executor_type: 'thread' or 'process'."""
    if isinstance(executor_type, str):
        et = executor_type.strip().lower()
        if et == "thread":
            executor_type = ExecutorType.THREAD
        elif et == "process":
            executor_type = ExecutorType.PROCESS
        else:
            raise ValueError(f"unknown executor_type: {executor_type!r}")
    return DynamicPool(max_workers=max_workers, executor_type=executor_type, **kwargs)


# --------------------------------------------------------------------------- #
# Self-test / demo
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    def work(n: int) -> int:
        time.sleep(0.05)
        return n * n

    print("=" * 60)
    print("DynamicPool self-test")
    print("=" * 60)

    with create_pool("thread", max_workers=4) as pool:
        futures = [pool.submit(work, i) for i in range(20)]
        results = [f.result(timeout=5) for f in futures]
        assert results == [i * i for i in range(20)]
        print(f"[THREAD ] results OK | metrics={pool.metrics.as_dict()}")

    with create_pool("process", max_workers=2) as pool:
        futures = [pool.submit(work, i) for i in range(8)]
        results = [f.result(timeout=10) for f in futures]
        assert results == [i * i for i in range(8)]
        print(f"[PROCESS] results OK | metrics={pool.metrics.as_dict()}")

    def boom() -> None:
        raise ValueError("intentional")

    with create_pool("thread", max_workers=2) as pool:
        f = pool.submit(boom)
        try:
            f.result(timeout=2)
        except ValueError as e:
            assert str(e) == "intentional"
        print(f"[ERROR  ] propagation OK | metrics={pool.metrics.as_dict()}")

    print("=" * 60)
    print("All self-tests passed.")
    print("=" * 60)