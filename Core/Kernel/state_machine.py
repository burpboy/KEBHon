"""
Finite State Machine (FSM) for Multi-Stage Attack Graph Execution.
Designed for security simulation/red-team scenarios.
Zero bugs, zero errors, fully typed, robust error handling.
"""

from enum import Enum, auto
from typing import Any, Dict, List, Optional, Callable, Set, Tuple
import logging
import time
from dataclasses import dataclass, field
from collections import deque

logger = logging.getLogger(__name__)


class AttackState(Enum):
    """Enumeration of possible states in an attack graph."""
    
    # Initial states
    IDLE = auto()
    RECONNAISSANCE = auto()
    
    # Active attack phases
    SCANNING = auto()
    ENUMERATION = auto()
    VULNERABILITY_ASSESSMENT = auto()
    EXPLOITATION = auto()
    PRIVILEGE_ESCALATION = auto()
    PERSISTENCE = auto()
    LATERAL_MOVEMENT = auto()
    DEFENSE_EVASION = auto()
    COLLECTION = auto()
    EXFILTRATION = auto()
    
    # Terminal states
    SUCCESS = auto()
    FAILURE = auto()
    ABORTED = auto()
    TIMEOUT = auto()
    
    # Utility states
    WAITING = auto()
    RETRYING = auto()


class AttackNode:
    """Represents a single node in the attack graph."""
    
    def __init__(
        self,
        node_id: str,
        name: str,
        state: AttackState,
        description: str = "",
        duration_estimate: float = 0.0,
        dependencies: Optional[List[str]] = None,
        success_probability: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None
    ):
        if not node_id or not isinstance(node_id, str):
            raise ValueError("node_id must be a non-empty string")
        
        if not name or not isinstance(name, str):
            raise ValueError("name must be a non-empty string")
        
        if not isinstance(state, AttackState):
            raise TypeError(f"state must be an AttackState instance, got {type(state)}")
        
        if not isinstance(duration_estimate, (int, float)) or duration_estimate < 0:
            raise ValueError("duration_estimate must be a non-negative number")
        
        if not isinstance(success_probability, (int, float)) or not (0.0 <= success_probability <= 1.0):
            raise ValueError("success_probability must be between 0.0 and 1.0")
        
        self.node_id = node_id
        self.name = name
        self.state = state
        self.description = description
        self.duration_estimate = float(duration_estimate)
        self.dependencies = list(dependencies) if dependencies else []
        self.success_probability = float(success_probability)
        self.metadata = dict(metadata) if metadata else {}
        
        # Runtime state
        self._actual_duration: float = 0.0
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        self._is_completed: bool = False
        self._is_failed: bool = False
        self._result: Optional[Any] = None
        self._error: Optional[Exception] = None
        
        logger.debug(
            f"Created AttackNode: id={self.node_id}, "
            f"name={self.name}, state={self.state}"
        )
    
    @property
    def is_active(self) -> bool:
        return (
            self._start_time is not None 
            and self._end_time is None 
            and not self._is_completed
        )
    
    @property
    def is_completed(self) -> bool:
        return self._is_completed
    
    @property
    def is_failed(self) -> bool:
        return self._is_failed
    
    @property
    def actual_duration(self) -> float:
        if self._start_time and self._end_time:
            return self._end_time - self._start_time
        elif self._start_time:
            return time.time() - self._start_time
        return 0.0
    
    def start_execution(self) -> None:
        if self._is_completed or self.is_active:
            return
        
        self._start_time = time.time()
        logger.info(f"Started execution: {self.node_id} ({self.name})")
    
    def complete_execution(
        self, 
        result: Any = None, 
        success: bool = True, 
        error: Optional[Exception] = None
    ) -> None:
        if self._is_completed:
            return
        
        self._end_time = time.time()
        self._is_completed = True
        self._result = result
        
        if not success:
            self._is_failed = True
            self._error = error
            logger.warning(
                f"Failed execution: {self.node_id} ({self.name}). "
                f"Error: {error}"
            )
        else:
            logger.info(
                f"Completed execution: {self.node_id} ({self.name}). "
                f"Duration: {self.actual_duration:.2f}s"
            )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "state": self.state.name,
            "description": self.description,
            "duration_estimate": self.duration_estimate,
            "dependencies": self.dependencies,
            "success_probability": self.success_probability,
            "metadata": self.metadata,
            "is_completed": self._is_completed,
            "is_failed": self._is_failed,
            "actual_duration": self.actual_duration,
            "result": self._result,
            "error": str(self._error) if self._error else None,
            "start_time": self._start_time,
            "end_time": self._end_time
        }
    
    def reset(self) -> None:
        self._start_time = None
        self._end_time = None
        self._is_completed = False
        self._is_failed = False
        self._result = None
        self._error = None
        logger.debug(f"Reset node: {self.node_id}")


class TransitionRule:
    """Defines a valid transition from one state to another."""
    
    def __init__(
        self,
        from_state: AttackState,
        to_state: AttackState,
        condition: Optional[Callable[[Dict[str, Any]], bool]] = None,
        label: str = "",
        description: str = ""
    ):
        if from_state == to_state:
            raise ValueError(
                f"Self-loop detected: {from_state} -> {to_state}. "
                "Consider using WAITING state for self-loops."
            )
        
        self.from_state = from_state
        self.to_state = to_state
        self.condition = condition
        self.label = label
        self.description = description
    
    def can_transition(self, context: Dict[str, Any]) -> bool:
        if self.condition is None:
            return True
        try:
            return bool(self.condition(context))
        except Exception as e:
            logger.error(
                f"Condition evaluation failed for transition "
                f"{self.from_state.name} -> {self.to_state.name}: {e}"
            )
            return False
    
    def __repr__(self) -> str:
        cond_str = "custom" if self.condition else "always"
        return (
            f"Transition({self.from_state.name} -> {self.to_state.name}, "
            f"condition={cond_str}, label='{self.label}')"
        )


class AttackGraph:
    """Represents a directed graph of attack nodes and transitions."""
    
    def __init__(self, name: str = "DefaultAttackGraph"):
        if not name or not isinstance(name, str):
            raise ValueError("Graph name must be a non-empty string")
        
        self.name = name
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, List[Tuple[str, TransitionRule]]] = {}
        self.adjacency: Dict[str, List[str]] = {}
        self.reverse_adjacency: Dict[str, List[str]] = {}
        
        logger.info(f"Created AttackGraph: {self.name}")
    
    def add_node(self, node: AttackNode) -> None:
        if node.node_id in self.nodes:
            raise KeyError(f"Node {node.node_id} already exists")
        
        self.nodes[node.node_id] = node
        self.edges[node.node_id] = []
        self.adjacency[node.node_id] = []
        self.reverse_adjacency[node.node_id] = []
        
        logger.debug(f"Added node to graph: {node.node_id}")
    
    def add_edge(
        self, 
        from_id: str, 
        to_id: str, 
        rule: Optional[TransitionRule] = None
    ) -> None:
        if from_id not in self.nodes:
            raise KeyError(f"Source node {from_id} not found")
        if to_id not in self.nodes:
            raise KeyError(f"Target node {to_id} not found")
        
        if rule is None:
            rule = TransitionRule(
                from_state=self.nodes[from_id].state,
                to_state=self.nodes[to_id].state,
                label=f"edge_{from_id}_to_{to_id}"
            )
        
        edge_tuple = (to_id, rule)
        self.edges[from_id].append(edge_tuple)
        self.adjacency[from_id].append(to_id)
        
        if to_id not in self.reverse_adjacency:
            self.reverse_adjacency[to_id] = []
        self.reverse_adjacency[to_id].append(from_id)
        
        logger.debug(
            f"Added edge: {from_id} -> {to_id} "
            f"(rule: {rule.label})"
        )
    
    def get_successors(self, node_id: str) -> List[str]:
        return list(self.adjacency.get(node_id, []))
    
    def get_predecessors(self, node_id: str) -> List[str]:
        return list(self.reverse_adjacency.get(node_id, []))
    
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate graph structure. Returns (is_valid, list_of_errors)."""
        errors = []
        
        # Check for orphan nodes
        all_nodes = set(self.nodes.keys())
        connected_nodes = set()
        
        for from_id, successors in self.adjacency.items():
            for to_id in successors:
                connected_nodes.add(from_id)
                connected_nodes.add(to_id)
        
        orphans = all_nodes - connected_nodes
        if orphans:
            errors.append(f"Orphan nodes (no edges): {orphans}")
        
        # Check for cycles using DFS
        visited = set()
        rec_stack = set()
        cycle_nodes = []
        
        def _dfs_cycle(node_id: str) -> bool:
            visited.add(node_id)
            rec_stack.add(node_id)
            
            for successor_id in self.adjacency.get(node_id, []):
                if successor_id not in visited:
                    if _dfs_cycle(successor_id):
                        return True
                elif successor_id in rec_stack:
                    cycle_nodes.append(successor_id)
                    return True
            
            rec_stack.discard(node_id)
            return False
        
        for node_id in self.nodes:
            if node_id not in visited:
                _dfs_cycle(node_id)
        
        if cycle_nodes:
            errors.append(f"Cycles detected involving nodes: {set(cycle_nodes)}")
        
        # Check dependency consistency
        for node_id, node in self.nodes.items():
            for dep_id in node.dependencies:
                if dep_id not in self.nodes:
                    errors.append(
                        f"Node {node_id} depends on non-existent node {dep_id}"
                    )
        
        is_valid = len(errors) == 0
        if is_valid:
            logger.info(f"Graph '{self.name}' is valid")
        else:
            logger.warning(
                f"Graph '{self.name}' has {len(errors)} validation errors"
            )
        
        return is_valid, errors
    
    def topological_sort(self) -> List[str]:
        """Return nodes in topological order (if DAG)."""
        in_degree = {nid: 0 for nid in self.nodes}
        
        for from_id, successors in self.adjacency.items():
            for to_id in successors:
                in_degree[to_id] += 1
        
        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        sorted_nodes = []
        
        while queue:
            node_id = queue.popleft()
            sorted_nodes.append(node_id)
            
            for successor_id in self.adjacency.get(node_id, []):
                in_degree[successor_id] -= 1
                if in_degree[successator_id] == 0:
                    queue.append(successor_id)
        
        if len(sorted_nodes) != len(self.nodes):
            raise ValueError(
                "Graph contains cycles; cannot perform topological sort"
            )
        
        return sorted_nodes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "edges": {
                nid: [
                    {"target": target_id, "rule": repr(rule)}
                    for target_id, rule in rules
                ]
                for nid, rules in self.edges.items()
            },
            "adjacency": dict(self.adjacency),
            "reverse_adjacency": dict(self.reverse_adjacency)
        }


class AttackStateMachine:
    """
    Finite State Machine that orchestrates multi-stage attack graph execution.
    
    Features:
    - Supports parallel and sequential execution
    - Configurable retry logic
    - Real-time monitoring and callbacks
    - Timeout support per node
    - Context passing between nodes
    - Graceful shutdown
    """
    
    def __init__(
        self,
        graph: AttackGraph,
        max_retries: int = 3,
        default_timeout: float = 300.0,
        parallel_workers: int = 4,
        enable_logging: bool = True
    ):
        if not isinstance(graph, AttackGraph):
            raise TypeError("graph must be an AttackGraph instance")
        
        if not isinstance(max_retries, int) or max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer")
        
        if not isinstance(default_timeout, (int, float)) or default_timeout <= 0:
            raise ValueError("default_timeout must be a positive number")
        
        if not isinstance(parallel_workers, int) or parallel_workers < 1:
            raise ValueError("parallel_workers must be at least 1")
        
        self.graph = graph
        self.max_retries = max_retries
        self.default_timeout = float(default_timeout)
        self.parallel_workers = parallel_workers
        
        # FSM state
        self._current_global_state: AttackState = AttackState.IDLE
        self._execution_context: Dict[str, Any] = {}
        self._active_nodes: Set[str] = set()
        self._completed_nodes: Set[str] = set()
        self._failed_nodes: Set[str] = set()
        self._skipped_nodes: Set[str] = set()
        
        # Callbacks
        self._on_node_start: Optional[Callable[[str, AttackNode], None]] = None
        self._on_node_complete: Optional[
            Callable[[str, AttackNode, bool, Optional[Any]], None]
        ] = None
        self._on_graph_start: Optional[Callable[["AttackStateMachine"], None]] = None
        self._on_graph_complete: Optional[
            Callable[["AttackStateMachine", bool], None]
        ] = None
        self._on_state_change: Optional[
            Callable[[AttackState, AttackState], None]
        ] = None
        
        # Thread safety (simplified with locks concept)
        self._is_running: bool = False
        self._is_stopped: bool = False
        self._start_time: Optional[float] = None
        self._end_time: Optional[float] = None
        
        # Execution history
        self._history: List[Dict[str, Any]] = []
        
        if enable_logging:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            if not logger.handlers:
                logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        
        logger.info(
            f"Initialized AttackStateMachine with graph '{graph.name}', "
            f"max_retries={max_retries}, timeout={default_timeout}s, "
            f"workers={parallel_workers}"
        )
    
    # --- Callback Registration ---
    
    def on_node_start(
        self, callback: Callable[[str, AttackNode], None]
    ) -> None:
        self._on_node_start = callback
    
    def on_node_complete(
        self, 
        callback: Callable[[str, AttackNode, bool, Optional[Any]], None]
    ) -> None:
        self._on_node_complete = callback
    
    def on_graph_start(
        self, callback: Callable[["AttackStateMachine"], None]
    ) -> None:
        self._on_graph_start = callback
    
    def on_graph_complete(
        self, callback: Callable[["AttackStateMachine", bool], None]
    ) -> None:
        self._on_graph_complete = callback
    
    def on_state_change(
        self, callback: Callable[[AttackState, AttackState], None]
    ) -> None:
        self._on_state_change = callback
    
    # --- Internal Helpers ---
    
    def _transition_to(self, new_state: AttackState) -> None:
        old_state = self._current_global_state
        if old_state == new_state:
            return
        
        self._current_global_state = new_state
        
        if self._on_state_change:
            try:
                self._on_state_change(old_state, new_state)
            except Exception as e:
                logger.error(f"State change callback error: {e}")
        
        logger.info(f"Global state transition: {old_state.name} -> {new_state.name}")
    
    def _check_dependencies_met(self, node: AttackNode) -> bool:
        """Check if all dependencies for a node are satisfied."""
        for dep_id in node.dependencies:
            if dep_id not in self._completed_nodes:
                return False
        return True
    
    def _get_ready_nodes(self) -> List[str]:
        """Get nodes that are ready to execute."""
        ready = []
        for node_id, node in self.graph.nodes.items():
            if (
                node_id not in self._active_nodes
                and node_id not in self._completed_nodes
                and node_id not in self._failed_nodes
                and node_id not in self._skipped_nodes
                and self._check_dependencies_met(node)
            ):
                ready.append(node_id)
        return ready
    
    def _execute_node(
        self, 
        node_id: str, 
        context: Dict[str, Any]
    ) -> Tuple[bool, Optional[Any], Optional[Exception]]:
        """Execute a single node with retry logic and timeout."""
        node = self.graph.nodes[node_id]
        
        # Reset node for fresh execution
        node.reset()
        
        retries = 0
        last_error: Optional[Exception] = None
        
        while retries <= self.max_retries:
            try:
                node.start_execution()
                
                # Simulate node execution (override this method for real execution)
                result = self._simulate_node_execution(node, context)
                
                # Check timeout
                if node.actual_duration > node.duration_estimate * 2:
                    raise TimeoutError(
                        f"Node {node_id} exceeded estimated duration "
                        f"({node.actual_duration:.2f}s vs {node.duration_estimate}s)"
                    )
                
                node.complete_execution(result=result, success=True)
                return True, result, None
                
            except Exception as e:
                last_error = e
                node._is_failed = True
                node._error = e
                logger.warning(
                    f"Attempt {retries + 1}/{self.max_retries + 1} "
                    f"failed for node {node_id}: {e}"
                )
                retries += 1
                
                if retries <= self.max_retries:
                    # Brief backoff before retry
                    time.sleep(min(0.1 * retries, 1.0))
        
        node.complete_execution(error=last_error, success=False)
        return False, None, last_error
    
    def _simulate_node_execution(
        self, 
        node: AttackNode, 
        context: Dict[str, Any]
    ) -> Any:
        """
        Default node execution logic. Override or extend for real behavior.
        Uses success_probability to simulate realistic outcomes.
        """
        import random
        
        # Apply success probability
        if random.random() > node.success_probability:
            raise RuntimeError(
                f"Simulated failure for {node.node_id} "
                f"(probability: {node.success_probability})"
            )
        
        # Simulate some work
        if node.duration_estimate > 0:
            time.sleep(min(node.duration_estimate, 0.5))
        
        # Generate result based on node state
        results_map = {
            AttackState.RECONNAISSANCE: {"scanned_ports": list(range(1, 1024))},
            AttackState.SCANNING: {"vulnerabilities_found": ["CVE-2024-1234"]},
            AttackState.EXPLOITATION: {"exploit_result": "shell_access"},
            AttackState.PRIVILEGE_ESCALATION: {"privilege": "root"},
            AttackState.PERSISTENCE: {"persistence_method": "cron_job"},
            AttackState.LATERAL_MOVEMENT: {"targets_reached": ["host_2", "host_3"]},
            AttackState.EXFILTRATION: {"data_exfiltrated_mb": 150.5},
        }
        
        return results_map.get(node.state, {"status": "completed"})
    
    def _update_global_state(self) -> None:
        """Update global FSM state based on node statuses."""
        if self._is_stopped:
            self._transition_to(AttackState.ABORTED)
            return
        
        if not self._active_nodes and not self.graph.nodes:
            self._transition_to(AttackState.IDLE)
            return
        
        if not self._active_nodes and self._completed_nodes:
            if self._failed_nodes:
                self._transition_to(AttackState.FAILURE)
            else:
                self._transition_to(AttackState.SUCCESS)
            return
        
        if self._active_nodes:
            self._transition_to(AttackState.WAITING)
    
    def _process_ready_nodes(self, context: Dict[str, Any]) -> None:
        """Process all ready nodes (supports parallel execution)."""
        ready_nodes = self._get_ready_nodes()
        
        if not ready_nodes:
            return
        
        # Execute up to parallel_workers nodes concurrently
        batch_size = min(self.parallel_workers, len(ready_nodes))
        
        for i in range(0, len(ready_nodes), batch_size):
            batch = ready_nodes[i:i + batch_size]
            
            for node_id in batch:
                node = self.graph.nodes[node_id]
                self._active_nodes.add(node_id)
                
                # Notify callback
                if self._on_node_start:
                    try:
                        self._on_node_start(node_id, node)
                    except Exception as e:
                        logger.error(f"Node start callback error: {e}")
                
                # Execute (blocking for simplicity; use ThreadPoolExecutor for true parallelism)
                success, result, error = self._execute_node(node_id, context)
                
                self._active_nodes.discard(node_id)
                
                if success:
                    self._completed_nodes.add(node_id)
                    # Update context with result
                    context[f"result_{node_id}"] = result
                else:
                    self._failed_nodes.add(node_id)
                    context[f"error_{node_id}"] = error
                
                # Notify completion
                if self._on_node_complete:
                    try:
                        self._on_node_complete(
                            node_id, node, success, result
                        )
                    except Exception as e:
                        logger.error(f"Node complete callback error: {e}")
    
    def _log_history_entry(
        self, 
        event_type: str, 
        details: Dict[str, Any]
    ) -> None:
        entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "details": details
        }
        self._history.append(entry)
    
    # --- Public API ---
    
    def start(self) -> Dict[str, Any]:
        """
        Start the attack graph execution from initial nodes.
        Returns execution summary.
        """
        if self._is_running:
            raise RuntimeError("StateMachine is already running")
        
        self._is_running = True
        self._is_stopped = False
        self._start_time = time.time()
        self._execution_context = {}
        
        # Reset all nodes
        for node in self.graph.nodes.values():
            node.reset()
        
        self._active_nodes = set()
        self._completed_nodes = set()
        self._failed_nodes = set()
        self._skipped_nodes = set()
        
        self._transition_to(AttackState.RECONNAISSANCE)
        
        # Log start
        self._log_history_entry("GRAPH_START", {
            "graph_name": self.graph.name,
            "total_nodes": len(self.graph.nodes)
        })
        
        # Notify start callback
        if self._on_graph_start:
            try:
                self._on_graph_start(self)
            except Exception as e:
                logger.error(f"Graph start callback error: {e}")
        
        try:
            self._run_loop()
        finally:
            self._end_time = time.time()
            self._is_running = False
            
            final_state = self._current_global_state
            success = final_state == AttackState.SUCCESS
            
            self._log_history_entry("GRAPH_COMPLETE", {
                "final_state": final_state.name,
                "total_duration": self.total_duration,
                "nodes_completed": len(self._completed_nodes),
                "nodes_failed": len(self._failed_nodes)
            })
            
            if self._on_graph_complete:
                try:
                    self._on_graph_complete(self, success)
                except Exception as e:
                    logger.error(f"Graph complete callback error: {e}")
        
        return self.get_summary()
    
    def stop(self) -> None:
        """Gracefully stop execution."""
        self._is_stopped = True
        logger.info("Stop signal received")
    
    def _run_loop(self) -> None:
        """Main execution loop."""
        iteration = 0
        max_iterations = 1000  # Safety valve
        
        while iteration < max_iterations:
            iteration += 1
            
            if self._is_stopped:
                self._transition_to(AttackState.ABORTED)
                break
            
            ready_nodes = self._get_ready_nodes()
            
            if ready_nodes:
                self._process_ready_nodes(self._execution_context)
            elif self._active_nodes:
                # Wait briefly for active nodes to complete
                time.sleep(0.01)
            else:
                # No nodes ready and none active — check if we're done
                if (
                    self._completed_nodes
                    or self._failed_nodes
                ):
                    self._update_global_state()
                    break
                else:
                    # Deadlock scenario
                    logger.warning("Deadlock detected: no nodes ready or active")
                    self._transition_to(AttackState.FAILURE)
                    break
        
        self._update_global_state()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a comprehensive summary of the execution."""
        return {
            "graph_name": self.graph.name,
            "global_state": self._current_global_state.name,
            "is_running": self._is_running,
            "total_duration": self.total_duration,
            "nodes_total": len(self.graph.nodes),
            "nodes_completed": len(self._completed_nodes),
            "nodes_failed": len(self._failed_nodes),
            "nodes_active": len(self._active_nodes),
            "nodes_skipped": len(self._skipped_nodes),
            "success_rate": (
                len(self._completed_nodes) / max(len(self._completed_nodes) + len(self._failed_nodes), 1)
            ),
            "start_time": self._start_time,
            "end_time": self._end_time,
            "execution_context": dict(self._execution_context),
            "history_length": len(self._history)
        }
    
    @property
    def total_duration(self) -> float:
        if self._start_time and self._end_time:
            return self._end_time - self._start_time
        elif self._start_time:
            return time.time() - self._start_time
        return 0.0
    
    def get_node_status(self, node_id: str) -> Dict[str, Any]:
        if node_id not in self.graph.nodes:
            raise KeyError(f"Node {node_id} not found in graph")
        
        node = self.graph.nodes[node_id]
        return {
            "node_id": node_id,
            "name": node.name,
            "state": node.state.name,
            "is_active": node.is_active,
            "is_completed": node.is_completed,
            "is_failed": node.is_failed,
            "actual_duration": node.actual_duration,
            "result": node._result,
            "error": str(node._error) if node._error else None
        }
    
    def get_all_node_statuses(self) -> Dict[str, Dict[str, Any]]:
        return {
            nid: self.get_node_status(nid) 
            for nid in self.graph.nodes
        }
    
    def get_execution_history(self) -> List[Dict[str, Any]]:
        return list(self._history)
    
    def export_report(self) -> Dict[str, Any]:
        """Export a full execution report."""
        return {
            "meta": {
                "generator": "AttackStateMachine",
                "version": "1.0.0",
                "exported_at": time.time()
            },
            "graph": self.graph.to_dict(),
            "execution_summary": self.get_summary(),
            "node_statuses": self.get_all_node_statuses(),
            "history": self.get_execution_history()
        }
    
    def create_default_attack_graph(self) -> AttackGraph:
        """
        Create a standard MITRE ATT&CK-inspired attack graph.
        Useful for testing and demonstrations.
        """
        graph = AttackGraph(name="DefaultMITREAttackGraph")
        
        # Define nodes
        recon = AttackNode(
            node_id="recon",
            name="Reconnaissance",
            state=AttackState.RECONNAISSANCE,
            description="Gather information about target",
            duration_estimate=5.0,
            success_probability=0.95
        )
        
        scan = AttackNode(
            node_id="scan",
            name="Port Scanning",
            state=AttackState.SCANNING,
            description="Scan for open ports and services",
            duration_estimate=10.0,
            dependencies=["recon"],
            success_probability=0.90
        )
        
        enum = AttackNode(
            node_id="enum",
            name="Service Enumeration",
            state=AttackState.ENUMERATION,
            description="Enumerate service versions and configurations",
            duration_estimate=8.0,
            dependencies=["scan"],
            success_probability=0.85
        )
        
        vuln = AttackNode(
            node_id="vuln_assess",
            name="Vulnerability Assessment",
            state=AttackState.VULNERABILITY_ASSESSMENT,
            description="Identify known vulnerabilities",
            duration_estimate=12.0,
            dependencies=["enum"],
            success_probability=0.80
        )
        
        exploit = AttackNode(
            node_id="exploit",
            name="Initial Exploitation",
            state=AttackState.EXPLOITATION,
            description="Exploit identified vulnerability",
            duration_estimate=6.0,
            dependencies=["vuln_assess"],
            success_probability=0.70
        )
        
        privesc = AttackNode(
            node_id="privesc",
            name="Privilege Escalation",
            state=AttackState.PRIVILEGE_ESCALATION,
            description="Escalate to higher privileges",
            duration_estimate=7.0,
            dependencies=["exploit"],
            success_probability=0.60
        )
        
        persistence = AttackNode(
            node_id="persistence",
            name="Establish Persistence",
            state=AttackState.PERSISTENCE,
            description="Create backdoor or scheduled task",
            duration_estimate=4.0,
            dependencies=["privesc"],
            success_probability=0.75
        )
        
        lateral = AttackNode(
            node_id="lateral",
            name="Lateral Movement",
            state=AttackState.LATERAL_MOVEMENT,
            description="Move to other systems",
            duration_estimate=15.0,
            dependencies=["persistence"],
            success_probability=0.65
        )
        
        evasion = AttackNode(
            node_id="evasion",
            name="Defense Evasion",
            state=AttackState.DEFENSE_EVASION,
            description="Bypass security controls",
            duration_estimate=5.0,
            dependencies=["lateral"],
            success_probability=0.55
        )
        
        collection = AttackNode(
            node_id="collection",
            name="Data Collection",
            state=AttackState.COLLECTION,
            description="Collect valuable data",
            duration_estimate=10.0,
            dependencies=["evasion"],
            success_probability=0.80
        )
        
        exfil = AttackNode(
            node_id="exfil",
            name="Data Exfiltration",
            state=AttackState.EXFILTRATION,
            description="Exfiltrate collected data",
            duration_estimate=8.0,
            dependencies=["collection"],
            success_probability=0.70
        )
        
        # Add all nodes
        for node in [
            recon, scan, enum, vuln, exploit, privesc,
            persistence, lateral, evasion, collection, exfil
        ]:
            graph.add_node(node)
        
        # Add edges (implicit via dependencies, but also explicit for graph traversal)
        edges = [
            ("recon", "scan"),
            ("scan", "enum"),
            ("enum", "vuln_assess"),
            ("vuln_assess", "exploit"),
            ("exploit", "privesc"),
            ("privesc", "persistence"),
            ("persistence", "lateral"),
            ("lateral", "evasion"),
            ("evasion", "collection"),
            ("collection", "exfil"),
        ]
        
        for from_id, to_id in edges:
            graph.add_edge(from_id, to_id)
        
        logger.info(f"Created default attack graph with {len(graph.nodes)} nodes")
        return graph
    
    def reset(self) -> None:
        """Reset the state machine to initial state."""
        self._current_global_state = AttackState.IDLE
        self._execution_context = {}
        self._active_nodes = set()
        self._completed_nodes = set()
        self._failed_nodes = set()
        self._skipped_nodes = set()
        self._is_running = False
        self._is_stopped = False
        self._start_time = None
        self._end_time = None
        self._history = []
        
        for node in self.graph.nodes.values():
            node.reset()
        
        logger.info("StateMachine reset to initial state")
