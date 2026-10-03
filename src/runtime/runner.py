"""Runtime-owned result/status handling around an injected Security Core."""

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from enums import Decision, ExecutionState, RunStatus, Stage
from errors import ErrorDetail
from schemas import ExecutionResult, SecurityDecision

from runtime.dto import RunIdentity, RuntimeDTO
from runtime.enforcement import Enforcement, EnforcementContractError
from runtime.ports import RunStatusUpdate


class RuntimeRunResult(RuntimeDTO):
    identity: RunIdentity
    run_status: RunStatus
    decision: SecurityDecision | None
    execution: ExecutionResult | None
    errors: list[ErrorDetail]
    output_allowed: bool
    forward_output: Any | None


class BoundEnforcement:
    """One candidate per evaluate call; no shared candidate lookup table."""

    def __init__(self, prepared, tools, record_execution, report_status):
        self._prepared = prepared.model_copy(deep=True) if prepared else None
        self._enforcement = Enforcement(tools)
        self._record_execution = record_execution
        self._report_status = report_status
        self._called = False
        self._result = None

    @property
    def result(self):
        return self._result.model_copy(deep=True) if self._result is not None else None

    def enforce(self, decision: SecurityDecision) -> ExecutionResult:
        if self._prepared is None:
            raise EnforcementContractError("No tool candidate bound to this call")
        if self._called:
            raise EnforcementContractError("Duplicate enforcement call")
        self._called = True
        self._report_status(RunStatus.ENFORCING)
        result = self._enforcement.enforce(self._prepared, decision)
        # Capture before any persistence or later Core failure.
        self._result = result.model_copy(deep=True)
        self._record_execution(result)
        self._report_status(RunStatus.VALIDATING)
        return result.model_copy(deep=True)


def select_output(decision, execution):
    """Only a successful execution and final ALLOW can publish tool output."""
    if (
        decision is None
        or decision.decision != Decision.ALLOW
        or execution is None
        or execution.execution_state != ExecutionState.EXECUTED
    ):
        return False, None
    output = deepcopy(execution.output)
    if decision.sanitized_output is not None:
        if (
            execution.tool_name != "read_file"
            or not isinstance(output, dict)
            or "content" not in output
        ):
            raise EnforcementContractError("Unsupported sanitized output target")
        output["content"] = decision.sanitized_output
    return True, output


def run_connected(adapter, request, *, tools, evidence, security_factory):
    request = request.model_copy(deep=True)
    identity = adapter.create_identity(request.session_id, request.scenario_id)
    errors = []
    evidence_failed = False
    decision = None
    core = None
    bound = None
    failed = False
    allowed, output = False, None

    def error(code, exc):
        return ErrorDetail(
            code=code,
            message="Runtime boundary operation failed",
            trace_id=identity.trace_id,
            details={"exception_type": type(exc).__name__},
        )

    def record(method, payload):
        nonlocal evidence_failed
        try:
            method(payload.model_copy(deep=True))
        except Exception as exc:  # noqa: BLE001
            evidence_failed = True
            errors.append(error("EVIDENCE_WRITE_FAILED", exc))

    def status(value):
        record(
            evidence.record_run_status,
            RunStatusUpdate(
                run_id=identity.run_id,
                trace_id=identity.trace_id,
                run_status=value,
                error=errors[0] if errors else None,
                updated_at=datetime.now(UTC),
            ),
        )

    status(RunStatus.CREATED)
    try:
        prepared = (
            adapter.prepare_tool_call(request, identity)
            if request.tool_request is not None
            else None
        )
        observation = (
            prepared.observation.model_copy(deep=True)
            if prepared
            else adapter.make_observation(
                identity, Stage.INPUT, request.user_input, request.context_items, None
            )
        )
        # evaluate starts at INPUT internally; keep its observation consistent at entry.
        observation.stage = Stage.INPUT
        record(evidence.record_observation, observation)
        bound = BoundEnforcement(
            prepared,
            tools,
            lambda result: record(evidence.record_execution, result),
            status,
        )
        core = security_factory(bound)
        status(RunStatus.VALIDATING)
        received = core.evaluate(observation.model_copy(deep=True))
        decision = SecurityDecision.model_validate(received.model_dump())
        if decision.run_id != identity.run_id or decision.trace_id != identity.trace_id:
            raise EnforcementContractError("Final decision ID mismatch")
        if prepared is not None and bound.result is None:
            raise EnforcementContractError("Core returned without an execution result")
        allowed, output = select_output(decision, bound.result)
    except Exception as exc:  # noqa: BLE001 — includes typed OrchestratorInternalError
        failed = True
        errors.append(error("RUNTIME_CONNECTION_FAILED", exc))
    finally:
        if core is not None:
            core_error = getattr(core, "last_evidence_error", None)
            if core_error is not None:
                evidence_failed = True
                errors.append(ErrorDetail.model_validate(core_error.model_dump()))
            try:
                core.close()
            except Exception as exc:  # noqa: BLE001
                failed = True
                errors.append(error("CORE_CLOSE_FAILED", exc))

    execution = bound.result if bound is not None else None
    if execution is not None and execution.execution_state == ExecutionState.FAILED:
        failed = True
        if execution.error is not None:
            errors.append(execution.error)
    if failed:
        allowed, output = False, None
    final_status = (
        RunStatus.FAILED
        if failed
        else RunStatus.PARTIAL_FAILURE
        if evidence_failed
        else RunStatus.COMPLETED
    )
    status(final_status)
    if final_status == RunStatus.COMPLETED and evidence_failed:
        final_status = RunStatus.PARTIAL_FAILURE
    return RuntimeRunResult(
        identity=identity,
        run_status=final_status,
        decision=decision,
        execution=execution,
        errors=errors,
        output_allowed=allowed,
        forward_output=output,
    )
