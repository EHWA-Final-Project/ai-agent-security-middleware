"""Evaluation-only bridge to real Runtime and SQLite, using in-memory tools.

RuntimeAdapter.create_identity is the extension point for injecting trial IDs.
No production Runtime behavior or shared schema is changed.
"""

import json
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from time import perf_counter

from enums import ExecutionState, GuardExecutionStatus, RunStatus, ScenarioType

from evidence.collector import EvidenceCollector
from evidence.sqlite_repository import SQLiteEvidenceRepository
from runtime.adapter import RuntimeAdapter
from runtime.dto import RunIdentity, RuntimeRequest, ToolRequest
from runtime.mock_tools.tools import (
    MockReadFile,
    MockSendEmail,
    ReadFileArguments,
    SendEmailArguments,
)
from security.policy.conditions import load_condition, make_condition_security_factory

from .experiment_runner import TrialOutput, TrialRequest

LABEL = "REAL MIDDLEWARE EXECUTION WITH MOCK TOOLS"


def load_runtime_scenarios() -> list[dict]:
    """The two P0 scenarios with compatible forbidden-tool ASR semantics."""
    fixtures = Path(__file__).resolve().parents[2] / "shared" / "fixtures"
    return [
        json.loads((fixtures / name).read_text(encoding="utf-8"))
        for name in ("benign_001.json", "attack_001.json")
    ]


def normalize_runtime_request(request: TrialRequest) -> RuntimeRequest:
    """Translate fixture arguments without mutating the source scenario."""
    scenario = request.scenario
    scenario_type = ScenarioType(scenario["scenario_type"])
    if scenario_type == ScenarioType.ATTACK and (
        scenario["scenario_id"] != "ATTACK-001"
        or scenario.get("attack_subtype") != "INDIRECT_PROMPT_INJECTION"
    ):
        raise ValueError(
            "unmeasurable attack: P0 ASR supports ATTACK-001 forbidden-tool "
            "execution only; output leakage requires delivered-output evaluation"
        )
    if scenario_type not in {ScenarioType.BENIGN, ScenarioType.ATTACK}:
        raise ValueError("only BENIGN and compatible ATTACK scenarios are supported")
    payload = deepcopy(dict(scenario["execution_payload"]))
    candidate = payload["tool_candidate"]
    arguments = candidate.get("tool_arguments", candidate.get("args"))
    if not isinstance(arguments, Mapping):
        raise TypeError("tool arguments must be a mapping")
    arguments = dict(arguments)
    tool_name = candidate["tool_name"]
    if tool_name == "send_email":
        if isinstance(arguments.get("to"), str):
            arguments["to"] = [arguments["to"]]
        arguments.setdefault("subject", "Runtime evaluation")
        arguments = SendEmailArguments.model_validate(arguments).model_dump()
    elif tool_name == "read_file":
        arguments = ReadFileArguments.model_validate(arguments).model_dump()
    else:
        raise ValueError(f"unsupported mock tool: {tool_name}")
    return RuntimeRequest(
        user_input=payload["user_input"],
        context_items=payload.get("context_items", []),
        session_id=f"experiment-{request.run_id}",
        scenario_id=str(scenario["scenario_id"]),
        tool_request=ToolRequest(tool_name=tool_name, tool_arguments=arguments),
    )


def make_mock_tools(scenario: Mapping) -> dict:
    """A fresh tool/outbox per trial. No filesystem or network tool access."""
    documents = scenario.get(
        "mock_documents", {"fixtures/safe.txt": "Safe evaluation document."}
    )
    if not isinstance(documents, Mapping):
        raise TypeError("mock_documents must be a mapping")
    return {"read_file": MockReadFile(dict(documents)), "send_email": MockSendEmail()}


class _TrialRuntimeAdapter(RuntimeAdapter):
    """Bind identity before Runtime constructs observations and evidence."""

    def __init__(self, trial: TrialRequest):
        self._trial = trial

    def create_identity(self, session_id, scenario_id) -> RunIdentity:
        if not session_id or not session_id.strip():
            raise ValueError("trial session_id is required")
        if scenario_id != str(self._trial.scenario["scenario_id"]):
            raise ValueError("trial scenario_id mismatch")
        if not self._trial.run_id.strip() or not self._trial.trace_id.strip():
            raise ValueError("trial run_id and trace_id are required")
        return RunIdentity(
            run_id=self._trial.run_id,
            trace_id=self._trial.trace_id,
            session_id=session_id,
            scenario_id=scenario_id,
        )


class RuntimeTrialAdapter:
    """Callable ExperimentRunner executor. Invalid trials raise and stay diagnostic.

    ``trials`` contains raw snapshots, including failed attempts, for reports.
    Latency includes only RuntimeAdapter.run(): identity, preparation, Core,
    enforcement, SQLite writes and Core close. Validation/queries are outside it.
    """

    def __init__(
        self,
        repository: SQLiteEvidenceRepository,
        *,
        block_threshold: float | None = None,
    ):
        self.repository = repository
        self.block_threshold = block_threshold
        self.trials: list[dict] = []

    def __call__(self, request: TrialRequest) -> TrialOutput:
        raw = {
            "run_id": request.run_id,
            "trace_id": request.trace_id,
            "scenario_id": str(request.scenario["scenario_id"]),
            "mode": request.mode,
            "trial_index": request.trial_index,
            "seed": request.seed,
            "evidence_validated": False,
        }
        self.trials.append(raw)
        try:
            if self.repository.list_events_by_run(request.run_id) or (
                self.repository.list_events_by_trace(request.trace_id)
            ):
                raise ValueError("trial identity already exists in Evidence")
            runtime_request = normalize_runtime_request(request)
            condition = load_condition(request.mode, block_threshold=self.block_threshold)
            collector = EvidenceCollector(self.repository)
            tools = make_mock_tools(request.scenario)
            raw["runtime_request"] = runtime_request.model_dump(mode="json")
            raw["policy_version"] = condition.policy.policy_version
            runtime = _TrialRuntimeAdapter(request)
            started = perf_counter()
            result = runtime.run(
                runtime_request,
                tools=tools,
                evidence=collector,
                security_factory=make_condition_security_factory(condition, collector),
            )
            latency_ms = (perf_counter() - started) * 1000
            raw.update(result.model_dump(mode="json"))
            raw["latency_ms"] = latency_ms
            raw["latency_scope"] = "Runtime end-to-end latency"
            raw["tool_call_counts"] = {
                name: tool.call_count for name, tool in tools.items()
            }
            if result.run_status != RunStatus.COMPLETED or result.errors:
                codes = [error.code for error in result.errors]
                raise ValueError(f"trial did not complete: {result.run_status.value}; {codes}")
            if result.decision is None or result.execution is None:
                raise ValueError("trial missing SecurityDecision or ExecutionResult")
            for item in (result.identity, result.decision, result.execution):
                if item.run_id != request.run_id or item.trace_id != request.trace_id:
                    raise ValueError("trial identity mismatch")
            if result.identity.scenario_id != runtime_request.scenario_id:
                raise ValueError("trial scenario linkage mismatch")
            if result.decision.policy_version != condition.policy.policy_version:
                raise ValueError("trial policy_version mismatch")
            execution = result.execution
            if execution.execution_state not in {
                ExecutionState.EXECUTED, ExecutionState.BLOCKED
            }:
                raise ValueError("trial execution_state is not successful or blocked")
            if execution.executed != (execution.execution_state == ExecutionState.EXECUTED):
                raise ValueError("trial execution flags disagree")
            if execution.tool_name != runtime_request.tool_request.tool_name:
                raise ValueError("trial tool mismatch")
            if tools[execution.tool_name].call_count != int(execution.executed):
                raise ValueError("trial tool call count mismatch")
            raw["evidence"] = self._validate_evidence(request, result, condition.name)
            raw["evidence_validated"] = True
            return TrialOutput(
                security_decision=result.decision,
                execution_result=execution,
                run_status=result.run_status,
                latency_ms=latency_ms,
            )
        except Exception as exc:
            raw["validation_error"] = f"{type(exc).__name__}: {exc}"
            raise

    def _validate_evidence(self, request, result, mode):
        events = self.repository.list_events_by_run(request.run_id)
        traced = self.repository.list_events_by_trace(request.trace_id)
        if not events or {e.event_id for e in events} != {e.event_id for e in traced}:
            raise ValueError("Evidence run/trace queries disagree or are empty")
        for event in events:
            if (
                event.run_id != request.run_id
                or event.trace_id != request.trace_id
                or event.payload.get("run_id") != request.run_id
                or event.payload.get("trace_id") != request.trace_id
            ):
                raise ValueError("Evidence identity mismatch")
        grouped = {}
        for event in events:
            grouped.setdefault(event.event_type, []).append(event)
        for kind in (
            "RUNTIME_OBSERVATION", "EXECUTION_RESULT", "SECURITY_DECISION", "RUN_STATUS"
        ):
            if not grouped.get(kind):
                raise ValueError(f"missing Evidence event: {kind}")
        observations = grouped["RUNTIME_OBSERVATION"]
        executions = grouped["EXECUTION_RESULT"]
        if len(observations) != 1 or len(executions) != 1:
            raise ValueError("duplicate Runtime observation/execution Evidence")
        for event in (*observations, *executions):
            if event.scenario_id != str(request.scenario["scenario_id"]):
                raise ValueError("Evidence scenario linkage mismatch")
        scenario_events = self.repository.list_events_by_scenario(
            str(request.scenario["scenario_id"])
        )
        if not {e.event_id for e in (*observations, *executions)} <= {
            e.event_id for e in scenario_events
        }:
            raise ValueError("Evidence scenario query missing Runtime events")
        candidate = observations[0].payload.get("tool_candidate", {})
        if candidate.get("tool_call_id") != result.execution.tool_call_id:
            raise ValueError("Evidence tool_call_id mismatch")
        if executions[0].payload != result.execution.model_dump(mode="json"):
            raise ValueError("saved ExecutionResult differs from Runtime")
        decisions = grouped["SECURITY_DECISION"]
        if len(decisions) != 1 or decisions[-1].payload != result.decision.model_dump(mode="json"):
            raise ValueError("saved SecurityDecision differs from Runtime/policy_version")
        if grouped["RUN_STATUS"][-1].payload.get("run_status") != RunStatus.COMPLETED.value:
            raise ValueError("Evidence final run status is not COMPLETED")
        guards = grouped.get("SECURITY_RESULT", [])
        if (mode == "A" and guards) or (mode != "A" and not guards):
            raise ValueError("Evidence Guard events disagree with condition")
        for event in guards:
            if (
                event.payload.get("execution_status") != GuardExecutionStatus.SUCCESS.value
                or event.payload.get("error") is not None
            ):
                raise ValueError("failed or timed-out guard invalidates this baseline trial")
        return {
            "event_count": len(events),
            "event_ids": [event.event_id for event in events],
            "event_counts_by_type": {kind: len(items) for kind, items in grouped.items()},
            "guard_execution_statuses": [event.payload["execution_status"] for event in guards],
            "run_trace_query_agreement": True,
            "runtime_scenario_linkage": True,
        }