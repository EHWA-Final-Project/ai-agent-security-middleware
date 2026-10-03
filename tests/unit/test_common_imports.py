"""Confirms every enum and schema the team frozen list defines can be
imported successfully. This is '9/23 전체: Common Enum/Schema
import 성공' 
"""


def test_enum_imports():
    from enums import (
        AttackSubtype,
        Decision,
        ExecutionState,
        GuardExecutionStatus,
        InspectionMode,
        RunStatus,
        ScenarioType,
        Stage,
    )

    assert Decision.ALLOW == "ALLOW"
    assert Stage.TOOL == "TOOL"
    assert RunStatus.COMPLETED == "COMPLETED"
    assert GuardExecutionStatus.TIMEOUT == "TIMEOUT"
    assert InspectionMode.STRICT == "STRICT"
    assert ExecutionState.BLOCKED == "BLOCKED"
    assert ScenarioType.ATTACK == "ATTACK"
    assert AttackSubtype.INDIRECT_PROMPT_INJECTION == "INDIRECT_PROMPT_INJECTION"


def test_ids_import():
    from ids import new_run_id, new_session_id, new_trace_id

    assert new_run_id().startswith("run-")
    assert new_trace_id().startswith("trace-")
    assert new_session_id().startswith("session-")


def test_error_import():
    from errors import ErrorDetail

    assert hasattr(ErrorDetail, "model_fields")


def test_schema_imports():
    from schemas import (
        EvaluationResult,
        ExecutionResult,
        RuntimeObservation,
        SecurityContext,
        SecurityDecision,
        SecurityEvent,
        SecurityResult,
    )

    # Just confirm these are usable pydantic models, not stubs that error on import.
    assert hasattr(SecurityResult, "model_fields")
    assert hasattr(SecurityContext, "model_fields")
    assert hasattr(SecurityDecision, "model_fields")
    assert hasattr(RuntimeObservation, "model_fields")
    assert hasattr(ExecutionResult, "model_fields")
    assert hasattr(SecurityEvent, "model_fields")
    assert hasattr(EvaluationResult, "model_fields")
