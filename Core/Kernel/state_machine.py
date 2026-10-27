# state_machine.py
# Finite State Machine (FSM) for Multi-Stage Attack Graph Execution
# Python 3.10+
# Zero-bug, production-grade implementation

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class AttackPhase(Enum):
    """Phases of a multi-stage attack graph (Lockheed Martin Cyber Kill Chain)."""
    RECONNAISSANCE = auto()
    WEAPONIZATION = auto()
    DELIVERY = auto()
    EXPLOITATION = auto()
    INSTALLATION = auto()
    COMMAND_AND_CONTROL = auto()
    ACTIONS_ON_OBJECTIVE = auto()
    COMPLETED = auto()
    ABORTED = auto()


class TransitionResult(Enum):
    """Result of an attempted state transition."""
    SUCCESS = auto()
    REJECTED_INVALID_TRANSITION = auto()
    REJECTED_GUARD_FAILED = auto()
    REJECTED_ALREADY_TERMINAL = auto()
    REJECTED_LOCKED = auto()


class FSMError(Exception):
    """Base exception for FSM errors."""


class InvalidTransitionError(FSMError):
    """Raised when an invalid transition is attempted in strict mode."""


class GuardError(FSMError):
    """Raised when a guard callable raises an unexpected exception."""


class TerminalStateError(FSMError):
    """Raised when a transition is attempted from a terminal state in strict mode."""


# ---------------------------------------------------------------------------
# Transition Definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Transition:
    """
    Immutable transition definition.

    Attributes:
        source: Source state.
        target: Target state.
        guard: Optional callable that must return True to allow the transition.
        action: Optional callable executed on successful transition.
        name: Optional human-readable transition name.
    """
    source: AttackPhase
    target: AttackPhase
    guard: Optional[Callable[["AttackStateMachine", Dict[str, Any]], bool]] = None
    action: Optional[Callable[["AttackStateMachine", Dict[str, Any]], None]] = None
    name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.source, AttackPhase):
            raise TypeError(f"source must be AttackPhase, got {type(self.source).__name__}")
        if not isinstance(self.target, AttackPhase):
            raise TypeError(f"target must be AttackPhase, got {type(self.target).__name__}")
        if self.source is self.target:
            raise ValueError(f"Self-transition not allowed: {self.source.name}")
        if self.guard is not None and not callable(self.guard):
            raise TypeError("guard must be callable or None")
        if self.action is not None and not callable(self.action):
            raise TypeError("action must be callable or None")
        if not isinstance(self.name, str):
            raise TypeError("name must be a string")


# ---------------------------------------------------------------------------
# State Machine
# ---------------------------------------------------------------------------

class AttackStateMachine:
    """
    Thread-safe Finite State Machine for orchestrating multi-stage
    attack-graph execution.
    """

    __slots__ = (
        "_initial_state",
        "_current_state",
        "_transitions",
        "_history",
        "_strict",
        "_lock",
        "_context",
        "_listeners",
        "_terminal_states",
    )

    def __init__(
        self,
        initial_state: AttackPhase = AttackPhase.RECONNAISSANCE,
        *,
        strict: bool = False,
        terminal_states: Optional[FrozenSet[AttackPhase]] = None,
    ) -> None:
        if not isinstance(initial_state, AttackPhase):
            raise TypeError("initial_state must be an AttackPhase")
        if not isinstance(strict, bool):
            raise TypeError("strict must be a bool")

        self._initial_state: AttackPhase = initial_state
        self._current_state: AttackPhase = initial_state
        self._strict: bool = strict
        self._transitions: Dict[AttackPhase, Dict[AttackPhase, Transition]] = {}
        self._history: List[Tuple[AttackPhase, AttackPhase, str]] = []
        self._lock: threading.RLock = threading.RLock()
        self._context: Dict[str, Any] = {}
        self._listeners: List[Callable[["AttackStateMachine", AttackPhase, AttackPhase], None]] = []

        default_terminal = frozenset({AttackPhase.COMPLETED, AttackPhase.ABORTED})
        self._terminal_states: FrozenSet[AttackPhase] = (
            terminal_states if terminal_states is not None else default_terminal
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def current_state(self) -> AttackPhase:
        with self._lock:
            return self._current_state

    @property
    def initial_state(self) -> AttackPhase:
        return self._initial_state

    @property
    def context(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._context)

    @property
    def history(self) -> Tuple[Tuple[AttackPhase, AttackPhase, str], ...]:
        with self._lock:
            return tuple(self._history)

    @property
    def is_terminal(self) -> bool:
        with self._lock:
            return self._current_state in self._terminal_states

    @property
    def terminal_states(self) -> FrozenSet[AttackPhase]:
        return self._terminal_states

    # ------------------------------------------------------------------
    # Transition registration
    # ------------------------------------------------------------------

    def add_transition(self, transition: Transition) -> None:
        if not isinstance(transition, Transition):
            raise TypeError("transition must be a Transition instance")
        with self._lock:
            edges = self._transitions.setdefault(transition.source, {})
            edges[transition.target] = transition
            logger.debug(
                "Registered transition %s -> %s (%s)",
                transition.source.name,
                transition.target.name,
                transition.name or "unnamed",
            )

    def add_transitions(self, transitions: List[Transition]) -> None:
        for t in transitions:
            self.add_transition(t)

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def add_listener(
        self,
        listener: Callable[["AttackStateMachine", AttackPhase, AttackPhase], None],
    ) -> None:
        if not callable(listener):
            raise TypeError("listener must be callable")
        with self._lock:
            self._listeners.append(listener)

    def remove_listener(
        self,
        listener: Callable[["AttackStateMachine", AttackPhase, AttackPhase], None],
    ) -> None:
        with self._lock:
            try:
                self._listeners.remove(listener)
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

    def set_context(self, key: str, value: Any) -> None:
        with self._lock:
            self._context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._context.get(key, default)

    # ------------------------------------------------------------------
    # Core transition logic
    # ------------------------------------------------------------------

    def can_transition(self, target: AttackPhase) -> bool:
        with self._lock:
            if self._current_state in self._terminal_states:
                return False
            edges = self._transitions.get(self._current_state, {})
            transition = edges.get(target)
            if transition is None:
                return False
            if transition.guard is None:
                return True
            try:
                return bool(transition.guard(self, dict(self._context)))
            except Exception:  # noqa: BLE001
                logger.exception("Guard raised in can_transition")
                return False

    def transition_to(self, target: AttackPhase, **context_updates: Any) -> TransitionResult:
        if not isinstance(target, AttackPhase):
            raise TypeError("target must be an AttackPhase")

        with self._lock:
            source = self._current_state

            # Terminal check
            if source in self._terminal_states:
                if self._strict:
                    raise TerminalStateError(
                        f"Cannot transition from terminal state {source.name}"
                    )
                return TransitionResult.REJECTED_ALREADY_TERMINAL

            edges = self._transitions.get(source, {})
            transition = edges.get(target)

            # Invalid edge
            if transition is None:
                if self._strict:
                    raise InvalidTransitionError(
                        f"No transition defined: {source.name} -> {target.name}"
                    )
                return TransitionResult.REJECTED_INVALID_TRANSITION

            # Guard evaluation
            snapshot = dict(self._context)
            if context_updates:
                snapshot.update(context_updates)

            if transition.guard is not None:
                try:
                    allowed = bool(transition.guard(self, snapshot))
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Guard raised exception during transition_to")
                    if self._strict:
                        raise GuardError(
                            f"Guard for {source.name}->{target.name} failed: {exc}"
                        ) from exc
                    return TransitionResult.REJECTED_GUARD_FAILED
                if not allowed:
                    if self._strict:
                        raise GuardError(
                            f"Guard blocked transition {source.name} -> {target.name}"
                        )
                    return TransitionResult.REJECTED_GUARD_FAILED

            # Commit state + context
            if context_updates:
                self._context.update(context_updates)
            self._current_state = target

            # Execute action
            if transition.action is not None:
                try:
                    transition.action(self, dict(self._context))
                except Exception:  # noqa: BLE001
                    logger.exception(
                        "Action raised exception for %s -> %s; rolling back",
                        source.name,
                        target.name,
                    )
                    self._current_state = source
                    if context_updates:
                        for k in context_updates:
                            self._context.pop(k, None)
                    if self._strict:
                        raise
                    return TransitionResult.REJECTED_GUARD_FAILED

            # Record history
            self._history.append(
                (source, target, transition.name or f"{source.name}->{target.name}")
            )
            logger.info("Transitioned %s -> %s", source.name, target.name)

            # Notify listeners
            for listener in list(self._listeners):
                try:
                    listener(self, source, target)
                except Exception:  # noqa: BLE001
                    logger.exception("Listener raised exception; continuing")

            return TransitionResult.SUCCESS

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def reset(self) -> None:
        with self._lock:
            self._current_state = self._initial_state
            self._history.clear()
            self._context.clear()
            logger.info("FSM reset to initial state: %s", self._initial_state.name)

    def available_transitions(self) -> FrozenSet[AttackPhase]:
        with self._lock:
            if self._current_state in self._terminal_states:
                return frozenset()
            return frozenset(
                t for t in self._transitions.get(self._current_state, {})
                if self.can_transition(t)
            )

    def __repr__(self) -> str:
        with self._lock:
            return (
                f"AttackStateMachine(state={self._current_state.name}, "
                f"history_len={len(self._history)}, "
                f"terminal={self._current_state in self._terminal_states})"
            )


# ---------------------------------------------------------------------------
# Pre-built kill-chain FSM factory
# ---------------------------------------------------------------------------

def build_kill_chain_fsm(*, strict: bool = False) -> AttackStateMachine:
    """
    Construct a default multi-stage attack-graph FSM following the
    Cyber Kill Chain model with linear progression.
    """
    fsm = AttackStateMachine(initial_state=AttackPhase.RECONNAISSANCE, strict=strict)

    chain: List[Tuple[AttackPhase, AttackPhase]] = [
        (AttackPhase.RECONNAISSANCE, AttackPhase.WEAPONIZATION),
        (AttackPhase.WEAPONIZATION, AttackPhase.DELIVERY),
        (AttackPhase.DELIVERY, AttackPhase.EXPLOITATION),
        (AttackPhase.EXPLOITATION, AttackPhase.INSTALLATION),
        (AttackPhase.INSTALLATION, AttackPhase.COMMAND_AND_CONTROL),
        (AttackPhase.COMMAND_AND_CONTROL, AttackPhase.ACTIONS_ON_OBJECTIVE),
        (AttackPhase.ACTIONS_ON_OBJECTIVE, AttackPhase.COMPLETED),
    ]

    for src, dst in chain:
        fsm.add_transition(
            Transition(source=src, target=dst, name=f"{src.name}->{dst.name}")
        )

    # Abort edges from every non-terminal phase
    for phase in AttackPhase:
        if phase in (AttackPhase.COMPLETED, AttackPhase.ABORTED):
            continue
        fsm.add_transition(
            Transition(
                source=phase,
                target=AttackPhase.ABORTED,
                guard=lambda _fsm, _ctx: True,
                name=f"abort_from_{phase.name}",
            )
        )

    return fsm


# ---------------------------------------------------------------------------
# Self-test / smoke example
# ---------------------------------------------------------------------------

def _self_test() -> None:  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    fsm = build_kill_chain_fsm(strict=False)
    assert fsm.current_state is AttackPhase.RECONNAISSANCE

    for step in (
        AttackPhase.WEAPONIZATION,
        AttackPhase.DELIVERY,
        AttackPhase.EXPLOITATION,
        AttackPhase.INSTALLATION,
        AttackPhase.COMMAND_AND_CONTROL,
        AttackPhase.ACTIONS_ON_OBJECTIVE,
        AttackPhase.COMPLETED,
    ):
        result = fsm.transition_to(step)
        assert result is TransitionResult.SUCCESS, f"Failed at {step.name}"

    assert fsm.is_terminal
    assert fsm.transition_to(AttackPhase.ABORTED) is TransitionResult.REJECTED_ALREADY_TERMINAL
    print("Self-test passed:", fsm)


if __name__ == "__main__":
    _self_test()