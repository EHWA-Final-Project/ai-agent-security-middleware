"""Deterministic scripted boundary replay, not a Guard or Agent implementation."""

from datetime import UTC, datetime

from schemas.evidence import SecurityEvent
from schemas.security import SecurityDecision, SecurityResult

from .external_mcp_adapter import record_sha256
from .external_mcp_trial_runner import ResolvedPolicy
from .mcp_trial_observation import CandidateObservation, ToolAction

FIXTURE_TIME = datetime(2000, 1, 1, tzinfo=UTC)  # Logical replay time, not a wall-clock claim.


def fixture_policy(config):
    suffix = "+pit01-simulated" if config.output_injection_scan else ""
    return ResolvedPolicy(f"fixture-simulated-{config.condition}-v1{suffix}", True,
                          {"simulated": True, "condition": config.condition})


class FixtureReplayBackend:
    backend_id = "external-mcp-scripted-fixture-v1"
    execution_scope = "fixture_execution"

    def __init__(self):
        self.events = {}

    def record(self, request, kind, payload):
        ref = f"{request.run_id}:{kind}"
        self.events[ref] = SecurityEvent(
            event_id=ref, run_id=request.run_id, trace_id=request.trace_id,
            scenario_id=request.case["scenario_id"], event_type=kind,
            payload=payload, created_at=FIXTURE_TIME,
        )
        return ref

    async def execute(self, request, observation):
        # Condition labels do NOT choose different replay behavior or claim policy quality.
        index = int(record_sha256({"sample": request.case["sample_id"]})[:8], 16) % 4
        behavior = ("executed", "warn", "pre_block", "post_block")[index]
        decision = "BLOCK" if behavior.endswith("block") else "WARN" if behavior == "warn" else "ALLOW"
        stage = "TOOL" if behavior == "pre_block" else "OUTPUT"
        action = ToolAction.model_validate(request.case["legitimate_tool_call"])
        base = self.record(request, "FIXTURE_REPLAY", {
            "run_id": request.run_id, "trace_id": request.trace_id,
            "behavior": behavior, "simulated_configuration": True,
            "mapped_case_sha256": record_sha256(request.case),
        })
        security = SecurityDecision(
            run_id=request.run_id, trace_id=request.trace_id, decision=decision,
            reason="Scripted fixture observation; no actual security policy evaluated",
            triggered_rules=["FIXTURE_REPLAY"], cumulative_risk_score=0.0,
            policy_version=request.policy.version,
        )
        guard = SecurityResult(
            run_id=request.run_id, trace_id=request.trace_id, stage=stage, guard_name="FixtureReplay",
            execution_status="SUCCESS", decision=decision, rule_ids=["FIXTURE_REPLAY"], latency_ms=0.0,
        )
        refs = [base, self.record(request, "SECURITY_DECISION", security.model_dump(mode="json")),
                self.record(request, "SECURITY_RESULT", guard.model_dump(mode="json"))]
        executed = behavior != "pre_block"
        delivered = behavior not in {"pre_block", "post_block"}
        # A fixed in-memory lookup exercises the pipeline without interpreting source text.
        if executed:
            documents = {"docs/benchmark.txt": request.case["document_content"]}
            if not isinstance(documents[action.arguments["path"]], str):
                raise ValueError("fixture document must be text")
        observation.candidates.append(CandidateObservation(
            candidate_id=f"{request.run_id}:candidate-0", timestamp=FIXTURE_TIME,
            server_name=action.server_name, tool_name=action.tool_name,
            candidate_source="fixture", requested_tool=action,
            security_decision=security, guard_decision=decision, guard_results=[guard],
            guard_decision_excludes_tool_policy=True, tool_policy_decision="ALLOW",
            pre_tool_block=not executed, warn=behavior == "warn", call_count=int(executed),
            tool_executed=executed, output_allowed=delivered, output_delivered=delivered,
            output_destination="model", post_tool_output_block=behavior == "post_block",
            evidence_refs=refs, prevention_sources=None,
            boundary_stage=stage, security_input_sha256=record_sha256(request.case),
        ))
        observation.run_status = "completed"
        observation.timed_out = False
        observation.candidate_trace_complete = True
        observation.guard_trace_complete = True
        observation.sdk_calls = []  # No actual SDK invocation; simulated receipts remain separate.
        observation.output_delivered = delivered
        observation.output_destination = "model"
        observation.evidence_refs = [base]
