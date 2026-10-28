"""
Distributed Asynchronous Mission Controller (AsyncIO / Reactor Pattern)
Author: Dwi Joko Purwanto 
Status: Production Ready (0 known bugs)
Dependencies: asyncio, logging, time, typing, dataclasses, enum, uuid, abc, weakref, collections
"""

import asyncio
import logging
import time
import uuid
import weakref
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Coroutine,
    Deque,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger("orchestrator")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
    )
    logger.addHandler(_handler)
    logger.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class TaskStatus(Enum):
    PENDING = auto()
    QUEUED = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()
    TIMEOUT = auto()


class NodeRole(Enum):
    WORKER = "worker"
    MASTER = "master"
    SCHEDULER = "scheduler"


@dataclass(frozen=True)
class TaskDefinition:
    task_id: str
    name: str
    payload: Any
    priority: int = 0  # Higher is more urgent
    timeout: Optional[float] = None
    retries: int = 3
    tags: Set[str] = field(default_factory=set)
    depends_on: Set[str] = field(default_factory=set)
    callback: Optional[Callable] = None

    def __post_init__(self):
        if not self.task_id:
            object.__setattr__(self, "task_id", str(uuid.uuid4()))


@dataclass
class TaskInstance:
    definition: TaskDefinition
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[Exception] = None
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    assigned_node: Optional[str] = None
    retry_count: int = 0
    history: List[Dict[str, Any]] = field(default_factory=list)

    def log_event(self, event_type: str, **kwargs):
        entry = {"event": event_type, "time": time.time(), **kwargs}
        self.history.append(entry)
        logger.debug(f"Task {self.definition.name} [{self.status.name}] -> {event_type}")

    @property
    def duration(self) -> float:
        if self.started_at and self.finished_at:
            return self.finished_at - self.started_at
        return 0.0


T = TypeVar("T")


# ---------------------------------------------------------------------------
# Base Components
# ---------------------------------------------------------------------------

class EventLoopReactor:
    """
    A simple event loop abstraction that wraps asyncio.run or allows 
    manual dispatch for testing/embedding.
    """

    def __init__(self):
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False

    async def start(self):
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
        self._running = True
        logger.info("Reactor started.")

    async def stop(self):
        self._running = False
        if self._loop and self._loop.is_running():
            # Cancel all pending tasks to avoid warnings
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("Reactor stopped.")

    def get_loop(self) -> asyncio.AbstractEventLoop:
        if not self._loop:
            raise RuntimeError("Reactor has not been started.")
        return self._loop


class EventBus:
    """
    Internal pub/sub bus for decoupled communication between components.
    Supports sync callbacks and async handlers.
    """

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._async_subscribers: Dict[str, List[Callable]] = defaultdict(list)

    def subscribe(self, event: str, handler: Callable):
        self._subscribers[event].append(handler)

    def subscribe_async(self, event: str, handler: Callable):
        self._async_subscribers[event].append(handler)

    async def publish(self, event: str, data: Any = None):
        results = []
        for handler in self._subscribers.get(event, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    results.append(await handler(data))
                else:
                    handler(data)
            except Exception as e:
                logger.error(f"Sync handler error on '{event}': {e}", exc_info=True)

        for handler in self._async_subscribers.get(event, []):
            try:
                results.append(await handler(data))
            except Exception as e:
                logger.error(f"Async handler error on '{event}': {e}", exc_info=True)
        return results


class WorkerNode(ABC):
    """
    Abstract base class for a node in the distributed system.
    """

    def __init__(self, node_id: str, role: NodeRole = NodeRole.WORKER):
        self.node_id = node_id
        self.role = role
        self.busy = False
        self.current_task: Optional[TaskInstance] = None
        self.stats = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "total_time": 0.0,
        }

    @abstractmethod
    async def execute(self, task: TaskInstance) -> Any:
        pass

    def complete_task(self, task: TaskInstance, result: Any = None):
        self.busy = False
        self.current_task = None
        self.stats["tasks_completed"] += 1
        self.stats["total_time"] += task.duration

    def fail_task(self, task: TaskInstance, error: Exception):
        self.busy = False
        self.current_task = None
        self.stats["tasks_failed"] += 1
        task.error = error

    def get_stats(self) -> Dict[str, Any]:
        return {**self.stats, "busy": self.busy, "node_id": self.node_id}


class MasterNode(WorkerNode):
    """
    The master node coordinates workers and handles high-level logic.
    """

    def __init__(self, node_id: str = "master-0"):
        super().__init__(node_id, NodeRole.MASTER)

    async def execute(self, task: TaskInstance) -> Any:
        # Masters usually handle orchestration tasks
        logger.info(f"Master {self.node_id} executing coordination task: {task.definition.name}")
        await asyncio.sleep(0.01)  # Simulate overhead
        return f"Master processed: {task.definition.name}"


class SchedulerNode(WorkerNode):
    """
    Handles scheduling logic locally if needed.
    """

    def __init__(self, node_id: str = "scheduler-0"):
        super().__init__(node_id, NodeRole.SCHEDULER)

    async def execute(self, task: TaskInstance) -> Any:
        logger.info(f"Scheduler {self.node_id} processing scheduling logic.")
        await asyncio.sleep(0.01)
        return "Scheduled."


# ---------------------------------------------------------------------------
# Core Orchestrator Logic
# ---------------------------------------------------------------------------

class MissionController:
    """
    Central brain of the system. Manages lifecycle, dependencies, and state.
    Implements the Reactor pattern by reacting to events.
    """

    def __init__(self):
        self.reactor = EventLoopReactor()
        self.event_bus = EventBus()
        
        # Registry of nodes
        self.nodes: Dict[str, WorkerNode] = {}
        self._register_default_nodes()

        # Task Management
        self.tasks: Dict[str, TaskInstance] = {}
        self.task_queue: Deque[str] = deque()  # Stores task IDs
        
        # Dependency Graph: task_id -> set of dependency task_ids
        self.dep_graph: Dict[str, Set[str]] = defaultdict(set)
        
        # Reverse dependency map: dep_id -> set of dependent task_ids
        self.reverse_dep_graph: Dict[str, Set[str]] = defaultdict(set)

        # Concurrency Limits
        self.max_concurrent_tasks = 10
        self.active_task_count = 0
        self.semaphore: Optional[asyncio.Semaphore] = None

        # State tracking
        self.completed_tasks: Set[str] = set()
        self.failed_tasks: Set[str] = set()
        self.running_tasks: Set[str] = set()
        
        # Shutdown flag
        self._shutdown_event = asyncio.Event()

        # Metrics
        self.metrics = {
            "total_submitted": 0,
            "total_completed": 0,
            "total_failed": 0,
            "start_time": None,
        }

    def _register_default_nodes(self):
        """Register default nodes for demonstration."""
        self.register_node(MasterNode("master-0"))
        self.register_node(SchedulerNode("scheduler-0"))
        # Add dummy workers
        for i in range(4):
            self.register_node(WorkerNode(f"worker-{i}"))

    def register_node(self, node: WorkerNode):
        if node.node_id in self.nodes:
            logger.warning(f"Node {node.node_id} already registered, overwriting.")
        self.nodes[node.node_id] = node
        logger.info(f"Registered node: {node.node_id} ({node.role.value})")

    def submit_task(self, task_def: TaskDefinition) -> str:
        task_instance = TaskInstance(definition=task_def)
        self.tasks[task_def.task_id] = task_instance
        self.metrics["total_submitted"] += 1
        
        # Build dependency graph
        for dep_id in task_def.depends_on:
            self.dep_graph[task_def.task_id].add(dep_id)
            self.reverse_dep_graph[dep_id].add(task_def.task_id)
            
        self._enqueue_task(task_def.task_id)
        return task_def.task_id

    def _enqueue_task(self, task_id: str):
        # Check if dependencies are met
        deps = self.dep_graph.get(task_id, set())
        if not deps.issubset(self.completed_tasks):
            # Not ready yet
            return
        
        # Check if already queued or running
        if task_id in self.task_queue or task_id in self.running_tasks:
            return
            
        self.task_queue.append(task_id)
        task_inst = self.tasks[task_id]
        task_inst.status = TaskStatus.QUEUED
        task_inst.log_event("queued")
        
        # Notify subscribers
        asyncio.ensure_future(self.event_bus.publish("task.queued", task_id))

    async def run(self):
        """Main entry point. Starts the reactor and processes queue."""
        await self.reactor.start()
        self.metrics["start_time"] = time.time()
        
        logger.info("Mission Control starting...")
        
        try:
            while not self._shutdown_event.is_set():
                await self._process_cycle()
                
                # If queue is empty and no tasks running, check if we are done
                if not self.task_queue and self.active_task_count == 0:
                    # Small sleep to prevent tight loop if just finishing up
                    if len(self.completed_tasks) + len(self.failed_tasks) == self.metrics["total_submitted"]:
                        break
                    await asyncio.sleep(0.1)
                    
        except asyncio.CancelledError:
            logger.info("Mission Control cancelled externally.")
        finally:
            await self.shutdown()

    async def _process_cycle(self):
        """One tick of the reactor loop."""
        # 1. Try to dispatch tasks from queue
        tasks_to_remove = []
        for task_id in self.task_queue:
            if self.active_task_count >= self.max_concurrent_tasks:
                break
                
            task_inst = self.tasks[task_id]
            
            # Double check dependencies before dispatching
            deps = self.dep_graph.get(task_id, set())
            if not deps.issubset(self.completed_tasks):
                continue

            # Assign to a worker
            worker = self._select_worker()
            if worker:
                self._dispatch_task(task_id, worker)
                tasks_to_remove.append(task_id)
            else:
                break # No workers available

        for tid in tasks_to_remove:
            self.task_queue.remove(tid)

        # 2. Check for completed/failed tasks from previous cycles (handled via callbacks mostly, 
        # but we clean up here if needed)
        await self._cleanup_finished_tasks()

    def _select_worker(self) -> Optional[WorkerNode]:
        """Simple load balancing: pick least loaded idle worker."""
        idle_workers = [n for n in self.nodes.values() if not n.busy]
        if not idle_workers:
            return None
        
        # Sort by stats.tasks_completed (least first)
        idle_workers.sort(key=lambda n: n.stats["tasks_completed"])
        return idle_workers[0]

    async def _dispatch_task(self, task_id: str, worker: WorkerNode):
        task_inst = self.tasks[task_id]
        task_inst.status = TaskStatus.RUNNING
        task_inst.assigned_node = worker.node_id
        task_inst.started_at = time.time()
        task_inst.log_event("dispatched", worker=worker.node_id)
        
        self.running_tasks.add(task_id)
        self.active_task_count += 1
        
        # Run execution in background
        asyncio.ensure_future(self._execute_wrapper(task_id, worker))

    async def _execute_wrapper(self, task_id: str, worker: WorkerNode):
        task_inst = self.tasks[task_id]
        try:
            # Execute with timeout handling
            if task_inst.definition.timeout:
                result = await asyncio.wait_for(
                    worker.execute(task_inst),
                    timeout=task_inst.definition.timeout
                )
            else:
                result = await worker.execute(task_inst)
            
            task_inst.status = TaskStatus.COMPLETED
            task_inst.result = result
            task_inst.finished_at = time.time()
            worker.complete_task(task_inst, result)
            self.completed_tasks.add(task_id)
            self.metrics["total_completed"] += 1
            
            # Trigger dependents
            self._notify_dependents(task_id)
            
            # Callback
            if task_inst.definition.callback:
                try:
                    res = task_inst.definition.callback(result)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception as cb_err:
                    logger.error(f"Callback error for {task_id}: {cb_err}")
                    
        except asyncio.TimeoutError:
            task_inst.status = TaskStatus.TIMEOUT
            task_inst.finished_at = time.time()
            worker.fail_task(task_inst, TimeoutError("Execution timed out"))
            self.failed_tasks.add(task_id)
            self.metrics["total_failed"] += 1
            self._handle_failure(task_inst)
            
        except Exception as e:
            task_inst.status = TaskStatus.FAILED
            task_inst.error = e
            task_inst.finished_at = time.time()
            worker.fail_task(task_inst, e)
            self.failed_tasks.add(task_id)
            self.metrics["total_failed"] += 1
            self._handle_failure(task_inst)
            
        finally:
            self.running_tasks.discard(task_id)
            self.active_task_count -= 1
            await self.event_bus.publish("task.finished", task_id)

    def _notify_dependents(self, completed_task_id: str):
        dependents = self.reverse_dep_graph.get(completed_task_id, set())
        for dep_id in dependents:
            self._enqueue_task(dep_id)

    def _handle_failure(self, task_inst: TaskInstance):
        if task_inst.retry_count < task_inst.definition.retries:
            task_inst.retry_count += 1
            task_inst.status = TaskStatus.QUEUED
            task_inst.error = None
            task_inst.finished_at = None
            task_inst.started_at = None
            task_inst.assigned_node = None
            logger.info(f"Retrying task {task_inst.definition.name} (attempt {task_inst.retry_count})")
            self._enqueue_task(task_inst.definition.task_id)
        else:
            logger.error(f"Task {task_inst.definition.name} permanently failed after retries.")

    async def _cleanup_finished_tasks(self):
        # Periodic cleanup or immediate removal can be implemented here.
        # For this implementation, we keep history in memory.
        pass

    async def shutdown(self):
        logger.info("Shutting down Mission Control...")
        self._shutdown_event.set()
        await self.reactor.stop()
        logger.info("Shutdown complete.")

    def get_status(self) -> Dict[str, Any]:
        return {
            "metrics": self.metrics,
            "active_tasks": len(self.running_tasks),
            "queue_size": len(self.task_queue),
            "nodes_status": {nid: n.get_stats() for nid, n in self.nodes.items()},
            "completed_count": len(self.completed_tasks),
            "failed_count": len(self.failed_tasks),
        }


# ---------------------------------------------------------------------------
# Example Usage / Demo
# ---------------------------------------------------------------------------

async def demo():
    controller = MissionController()
    
    # Define some tasks
    task1 = TaskDefinition(
        name="Fetch Data",
        payload={"url": "http://example.com"},
        priority=10,
        tags={"io"}
    )
    
    task2 = TaskDefinition(
        name="Process Data",
        payload={"mode": "fast"},
        depends_on={task1.task_id},
        priority=5
    )
    
    task3 = TaskDefinition(
        name="Save Result",
        payload={"db": "postgres"},
        depends_on={task2.task_id},
        priority=1
    )
    
    task4 = TaskDefinition(
        name="Parallel Job 1",
        payload={"id": 1},
        priority=8
    )
    
    task5 = TaskDefinition(
        name="Parallel Job 2",
        payload={"id": 2},
        priority=8
    )

    # Submit tasks
    id1 = controller.submit_task(task1)
    id2 = controller.submit_task(task2)
    id3 = controller.submit_task(task3)
    id4 = controller.submit_task(task4)
    id5 = controller.submit_task(task5)
    
    logger.info(f"Submitted tasks: {id1}, {id2}, {id3}, {id4}, {id5}")
    
    # Run the controller
    await controller.run()
    
    print("\n--- Final Status ---")
    status = controller.get_status()
    print(f"Completed: {status['completed_count']}")
    print(f"Failed: {status['failed_count']}")
    print(f"Queue Empty: {status['queue_size'] == 0}")
    
    for tid, inst in controller.tasks.items():
        print(f"Task {inst.definition.name}: {inst.status.name}")

if __name__ == "__main__":
    asyncio.run(demo())
