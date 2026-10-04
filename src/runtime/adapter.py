"""Runtime 입력을 관측 객체로 변환하는 지원 담당 Adapter."""

from copy import deepcopy
from datetime import UTC, datetime
from uuid import uuid4

from enums import Stage
from ids import new_run_id, new_session_id, new_trace_id
from schemas import RuntimeObservation

from runtime.dto import (
    PreparedToolCall,
    RunIdentity,
    RuntimeRequest,
    ToolCandidate,
    ToolRequest,
)


class RuntimeAdapter:
    def create_identity(
        self,
        session_id: str | None,
        scenario_id: str | None,
    ) -> RunIdentity:
        if session_id is not None and not session_id.strip():
            raise ValueError("session_id는 빈 문자열일 수 없습니다.")

        return RunIdentity(
            run_id=new_run_id(),
            session_id=(session_id if session_id is not None else new_session_id()),
            trace_id=new_trace_id(),
            scenario_id=scenario_id,
        )

    def create_tool_candidate(
        self,
        tool_request: ToolRequest,
    ) -> ToolCandidate:
        return ToolCandidate(
            tool_call_id=f"tool-{uuid4()}",
            tool_name=tool_request.tool_name,
            tool_arguments=deepcopy(tool_request.tool_arguments),
        )

    def make_observation(
        self,
        identity: RunIdentity,
        stage: Stage,
        user_input: str,
        context_items: list,
        tool_candidate: ToolCandidate | None,
    ) -> RuntimeObservation:
        if stage == Stage.TOOL and tool_candidate is None:
            raise ValueError("TOOL 단계에는 ToolCandidate가 필요합니다.")

        return RuntimeObservation(
            run_id=identity.run_id,
            session_id=identity.session_id,
            trace_id=identity.trace_id,
            scenario_id=identity.scenario_id,
            stage=stage,
            user_input=user_input,
            context_items=deepcopy(context_items),
            tool_candidate=(
                deepcopy(tool_candidate.model_dump())
                if tool_candidate is not None
                else None
            ),
            created_at=datetime.now(UTC),
        )

    def prepare_tool_call(
        self,
        request: RuntimeRequest,
        identity: RunIdentity,
    ) -> PreparedToolCall:
        if request.tool_request is None:
            raise ValueError("준비할 Tool 요청이 없습니다.")

        if request.scenario_id != identity.scenario_id:
            raise ValueError("요청과 실행의 scenario_id가 다릅니다.")

        if request.session_id is not None and request.session_id != identity.session_id:
            raise ValueError("요청과 실행의 session_id가 다릅니다.")

        candidate = self.create_tool_candidate(request.tool_request)

        observation = self.make_observation(
            identity=identity,
            stage=Stage.TOOL,
            user_input=request.user_input,
            context_items=request.context_items,
            tool_candidate=candidate,
        )

        return PreparedToolCall(
            observation=observation,
            candidate=candidate,
        )

    def run(self, request, *, tools, evidence, security_factory):
        """Sprint 2: 호출마다 독립된 Orchestrator/Enforcement를 구성한다."""
        from runtime.runner import run_connected

        return run_connected(
            self,
            request,
            tools=tools,
            evidence=evidence,
            security_factory=security_factory,
        )
