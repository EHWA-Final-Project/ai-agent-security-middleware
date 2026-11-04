"""Experiment conditions A / B / C.

A condition is one YAML file under ``condition_configs/`` holding both the policy
fields (thresholds, weights, coordination_mode, policy_version) and a
``guards:`` section (which Guards are enabled). Switching condition means
switching the file, never editing code.

    A  No Guard            all Guards disabled
    B  Independent Guards  coordination_mode: independent
    C  Cross-layer Guards  coordination_mode: linked

D (Adaptive Inspection) is added after A/B/C results exist.

Identifying the condition in stored data: every condition has its own
``policy_version`` (``v0.1.0-cond-a-no-guard`` / ``-cond-b-independent`` /
``-cond-c-linked``) and every SECURITY_DECISION carries it. Use
``condition_from_policy_version`` to turn it back into "A" / "B" / "C". A has no
SECURITY_RESULT events because all of its Guards are disabled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from security.plugins.guards.context_guard import ContextGuard
from security.plugins.guards.input_guard import InputGuard
from security.plugins.guards.output_guard import OutputGuard
from security.plugins.guards.tool_guard import ToolGuard
from security.plugins.manager import PluginManager
from security.policy.config import PolicyConfig, load_policy_config

_CONDITION_IN_VERSION = re.compile(r"-cond-([abc])-", re.IGNORECASE)

CONDITIONS_DIR = Path(__file__).resolve().parent / "condition_configs"

CONDITION_FILES: dict[str, str] = {
    "A": "a_no_guard.yaml",
    "B": "b_independent.yaml",
    "C": "c_linked.yaml",
}


@dataclass(frozen=True)
class Condition:
    """One loaded experiment condition.

    ``name`` is "A", "B" or "C"; ``config_path`` is the YAML file it was loaded
    from; ``policy`` is the validated PolicyConfig (thresholds, weights,
    coordination_mode, policy_version).
    """

    name: str
    config_path: Path
    policy: PolicyConfig


def condition_path(name: str) -> Path:
    """Path of the YAML file for condition ``name`` (case-insensitive "A"/"B"/"C").

    Raises ValueError for any other name.
    """
    try:
        return CONDITIONS_DIR / CONDITION_FILES[name.upper()]
    except KeyError:
        raise ValueError(
            f"unknown condition {name!r}; expected one of {sorted(CONDITION_FILES)}"
        ) from None


def load_condition(name: str, *, block_threshold: float | None = None) -> Condition:
    """Load a condition's policy.

    Returns a ``Condition``. Raises ValueError for an unknown name.

    ``block_threshold`` overrides the file value for threshold sweeps. Because
    any threshold change must change policy_version, the override is appended
    to it (e.g. ``v0.1.0-cond-c-linked+block0.92``).
    """
    path = condition_path(name)
    policy = load_policy_config(path)
    if block_threshold is not None and block_threshold != policy.block_threshold:
        policy = policy.model_copy(
            update={
                "block_threshold": block_threshold,
                "policy_version": f"{policy.policy_version}+block{block_threshold:g}",
            }
        )
    return Condition(name=name.upper(), config_path=path, policy=policy)


def build_plugin_manager(condition: Condition, *, tool_policy=None) -> PluginManager:
    """Register all four Guards, then apply the condition's enabled flags.

    Returns a PluginManager whose enabled Guards match the condition file
    (none for A, all four for B and C).

    ``tool_policy`` (a ``ToolPolicy``) sets the Tool Guard's allowlist and
    argument scope; ``None`` keeps the baseline behaviour.
    """
    manager = PluginManager()
    for guard in (InputGuard(), ContextGuard(), ToolGuard(tool_policy), OutputGuard()):
        manager.register_guard(guard)
    manager.load_from_config(str(condition.config_path))
    return manager


def make_condition_security_factory(
    condition: Condition, evidence_sink, *, guard_timeout_sec=2.0, tool_policy=None
):
    """Security factory for ``run_connected`` / ``RuntimeAdapter.run`` driven by a condition.

    Same shape as ``runtime.composition.make_security_factory`` but the policy and
    the enabled Guards come from the condition file, so Runtime/Evidence runs can
    be repeated under A, B and C without code changes.

    Returns ``factory(enforcement) -> SecurityOrchestrator``. A new Orchestrator
    is built per call, as in ``run_connected``. Each SECURITY_DECISION written
    through ``evidence_sink`` carries ``condition.policy.policy_version``.
    """
    from security.orchestrator.orchestrator import SecurityOrchestrator

    def factory(enforcement):
        return SecurityOrchestrator(
            build_plugin_manager(condition, tool_policy=tool_policy),
            condition.policy,
            enforcement,
            evidence_sink,
            guard_timeout_sec=guard_timeout_sec,
        )

    return factory


def condition_from_policy_version(policy_version: str) -> str | None:
    """Return "A", "B" or "C" for a stored ``policy_version``, or None if it is not one.

    Works with threshold-override suffixes (``...-cond-c-linked+block0.92``).
    """
    match = _CONDITION_IN_VERSION.search(policy_version or "")
    return match.group(1).upper() if match else None
