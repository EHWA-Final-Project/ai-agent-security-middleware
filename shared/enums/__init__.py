"""Common Enum · v1

Frozen shared enum definitions. These are referenced across all owners
(Fatin / 지원 / Wana / 지송) — do not rename values without a team-wide sync,
since downstream code (Evidence, Evaluation, Enforcement) matches on them
by exact string value.
"""

from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"


class InspectionMode(str, Enum):
    FAST = "FAST"  # P1 Adaptive only — not active in P0
    STANDARD = "STANDARD"
    STRICT = "STRICT"


class Stage(str, Enum):
    INPUT = "INPUT"
    CONTEXT = "CONTEXT"
    TOOL = "TOOL"
    OUTPUT = "OUTPUT"


class ExecutionState(str, Enum):
    """State of a single tool call."""

    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class RunStatus(str, Enum):
    """State of an entire run (run_id). VALIDATING <-> ENFORCING may repeat
    if the run involves multiple tool calls.
    """

    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    ENFORCING = "ENFORCING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"


class GuardExecutionStatus(str, Enum):
    """Success/failure of the Guard's own execution — separate from the
    security Decision it produces. A Guard that times out has
    execution_status=TIMEOUT and decision=None, never a fabricated Decision.
    """

    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class ScenarioType(str, Enum):
    BENIGN = "BENIGN"
    ATTACK = "ATTACK"
    ERROR = "ERROR"


class AttackSubtype(str, Enum):
    """P0/P1 candidates only — scope frozen for this cycle.
    MEMORY_POISONING is out of scope (P2/Future Work).
    """

    DIRECT_PROMPT_INJECTION = "DIRECT_PROMPT_INJECTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    PROMPT_EXTRACTION = "PROMPT_EXTRACTION"
    TOOL_MISUSE = "TOOL_MISUSE"
    DATA_LEAKAGE = "DATA_LEAKAGE"
