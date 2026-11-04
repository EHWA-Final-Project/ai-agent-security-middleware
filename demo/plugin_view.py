"""Presentation only: current architecture and replay of persisted events."""

import streamlit as st

STAGES = ("INPUT", "CONTEXT", "TOOL", "OUTPUT")


@st.cache_data
def architecture_config():
    """Inspect the existing composition without evaluating or running any tool.

    This describes current source, never the historical configuration of a run.
    The demo overrides only policy_version; coordination uses PolicyConfig defaults.
    """
    from runtime.composition import make_security_factory
    from security.policy.config import PolicyConfig

    core = make_security_factory(PolicyConfig(policy_version="architecture-preview"), None)(None)
    try:
        return {
            "mode": core.policy_config.coordination_mode.value,
            "plugins": [
                {"name": item.plugin.name, "stage": item.plugin.stage.value, "enabled": item.enabled}
                for item in core.plugin_manager.registry.all_guards()
            ],
        }
    finally:
        core.close()


def condition_config(mode):
    from security.policy.conditions import build_plugin_manager, load_condition

    condition = load_condition(mode)
    manager = build_plugin_manager(condition)
    return {
        "mode": condition.policy.coordination_mode.value,
        "plugins": [
            {"name": item.plugin.name, "stage": item.plugin.stage.value, "enabled": item.enabled}
            for item in manager.registry.all_guards()
        ],
    }


def event_label(event):
    payload = event["payload"]
    kind = event["event_type"]
    if kind == "SECURITY_RESULT":
        return f"🧩 {payload.get('guard_name', 'Guard')} · {payload.get('stage', '—')}"
    return {
        "RUNTIME_OBSERVATION": "Runtime Observation",
        "SECURITY_DECISION": "SecurityDecision",
        "EXECUTION_RESULT": "Enforcement · ExecutionResult",
        "RUN_STATUS": "Runtime Status",
    }.get(kind, kind)


def event_status(event):
    payload = event["payload"]
    return payload.get("decision") or payload.get("execution_state") or payload.get("run_status") or "—"


def show_status(decision, execution_status=None):
    if execution_status in ("ERROR", "TIMEOUT"):
        st.error(f"{execution_status} · {decision or '판정 없음'}")
    elif decision == "BLOCK":
        st.error("BLOCK")
    elif decision == "WARN":
        st.warning("WARN")
    elif decision == "ALLOW":
        st.success("ALLOW")
    else:
        st.caption(decision or "결과 기록 없음")


def replay_rows(events, cursor):
    """Preserve repository order, IDs and every event, including repeated stages."""
    return [
        {
            "Replay": "▶ CURRENT" if index == cursor else "✓ 완료" if index < cursor else "○ pending",
            "Event": event_label(event), "Result": event_status(event),
            "Stage": event.get("stage") or "—", "event_id": event["event_id"],
            "created_at": event["created_at"],
        }
        for index, event in enumerate(events)
    ]


def replay_caption(events, cursor):
    """Keep position, timestamp and result in one UI update from the same event."""
    if cursor < 0:
        return f"저장 Evidence 0/{len(events)} · 재생 준비"
    event = events[cursor]
    return (
        f"저장 Evidence {cursor + 1}/{len(events)} · {event['created_at']} · "
        f"{event_label(event)}: {event_status(event)}"
    )


def evidence_status(events, snapshot):
    """Confirm only what the SQLite query and completed Runtime result support."""
    if not events:
        return "기록 없음"
    identity = snapshot["result"]["identity"]
    matched = all(
        event["run_id"] == identity["run_id"] and event["trace_id"] == identity["trace_id"]
        and event["payload"].get("run_id") == identity["run_id"]
        and event["payload"].get("trace_id") == identity["trace_id"]
        for event in events
    )
    result = snapshot["result"]
    if matched and not result.get("errors") and result.get("run_status") == "COMPLETED":
        return "저장 확인"
    return "확인 필요"


def pipeline_step(events, cursor, kinds, stage=None):
    """Replay position comes only from matching real events, never stage order."""
    matches = [
        index for index, event in enumerate(events)
        if event["event_type"] in kinds and (stage is None or event["payload"].get("stage") == stage)
    ]
    seen = [index for index in matches if index <= cursor]
    if not matches:
        phase = "missing"
    elif cursor in matches:
        phase = "current"
    elif seen:
        phase = "complete" if len(seen) == len(matches) else "visited"
    else:
        phase = "pending"
    return {"phase": phase, "events": [events[index] for index in seen]}


def render_phase(step):
    phase = step["phase"]
    if phase == "current":
        st.info("▶ 현재 단계")
    elif phase == "complete":
        st.caption("✓ 재생 완료")
    elif phase == "visited":
        st.caption("↻ 일부 기록 확인")
    elif phase == "pending":
        st.caption("○ 재생 대기")
    else:
        st.caption("— 결과 기록 없음")


def render_pipeline(config, events, cursor):
    # The horizontal layout is architecture. Highlighting uses event indices only.
    columns = st.columns([1.1, 1.2, 1.5, 1.5, 1.5, 1.5])
    runtime = pipeline_step(events, cursor, {"RUNTIME_OBSERVATION", "RUN_STATUS"})
    with columns[0], st.container(border=True):
        st.caption("시작 →")
        st.markdown("**Runtime**")
        render_phase(runtime)
        if runtime["events"]:
            st.caption(event_status(runtime["events"][-1]))
    with columns[1], st.container(border=True):
        st.caption("연결 →")
        st.markdown("**Plugin Manager**")
        st.caption("🧩 Guard 플러그인 연결")
        st.caption("구조 설명 · 별도 이벤트 없음")
    for stage, column in zip(STAGES, columns[2:], strict=True):
        step = pipeline_step(events, cursor, {"SECURITY_RESULT"}, stage)
        with column, st.container(border=True):
            st.caption("Guard Plugin →")
            st.markdown(f"**🧩 {stage}**")
            render_phase(step)
            for event in step["events"]:
                payload = event["payload"]
                st.caption(payload.get("guard_name", "Guard"))
                show_status(payload.get("decision"), payload.get("execution_status"))
                if payload.get("risk_score") is not None:
                    st.write(f"Risk {payload['risk_score']:.3f}")
                if payload.get("latency_ms") is not None:
                    st.caption(f"{payload['latency_ms']:.3f} ms")
                if payload.get("reason"):
                    st.caption(str(payload["reason"]))
    with st.expander("Cross-layer Coordination · 플러그인 구성과 데이터 출처", expanded=False):
        st.write("Linked mode에서는 앞 단계 Guard 결과가 SecurityContext에 누적되어 후속 판단에 반영됩니다.")
        st.caption(f"구조 설명 · 현재 코드 coordination: {config['mode']} · 선택 run의 저장 설정이 아닙니다.")
        st.dataframe(config["plugins"], hide_index=True, width="stretch")
        st.caption("Custom Guard 시연: examples/custom_guard.py의 BlockedTermGuard를 register_guard()로 등록합니다. 운영 서비스의 hot-swap 기능이 아닙니다.")
        st.code("uv run python examples/custom_guard.py\nuv run --group demo pytest tests/contract/test_custom_guard_plugin.py -q", language="powershell")
        st.caption("현재 구성은 기존 make_security_factory / PolicyConfig에서 읽습니다. 과거 run의 Enabled / coordination을 추론하지 않습니다.")
        st.caption("SecurityContext의 inspection_mode / STRICT 전환은 Evidence에 저장되지 않아 표시하지 않습니다.")


def render_outcome(events, cursor, snapshot):
    final, enforcement, evidence = st.columns(3)
    decision_step = pipeline_step(events, cursor, {"SECURITY_DECISION"})
    execution_step = pipeline_step(events, cursor, {"EXECUTION_RESULT"})
    decision = decision_step["events"][-1]["payload"] if decision_step["events"] else {}
    execution = execution_step["events"][-1]["payload"] if execution_step["events"] else {}
    with final, st.container(border=True):
        st.caption("④ 최종 보안 판정 →")
        st.markdown("**SecurityDecision**")
        render_phase(decision_step)
        show_status(decision.get("decision"))
        if decision:
            st.caption(decision.get("reason", ""))
    with enforcement, st.container(border=True):
        st.caption("실행 제어 →")
        st.markdown("**Enforcement**")
        render_phase(execution_step)
        if execution:
            st.write("Tool 실행:", "실행됨" if execution.get("executed") is True else "미실행" if execution.get("executed") is False else "기록 없음")
            st.caption(execution.get("execution_state", "—"))
    with evidence, st.container(border=True):
        st.caption("⑤ 저장 자료 · Replay와 별도")
        st.markdown("**Evidence · SQLite**")
        st.metric("저장 이벤트", f"{len(events)}건")
        if snapshot:
            status = evidence_status(events, snapshot)
            if status == "저장 확인":
                st.success("SQLite persistence OK · 저장 확인")
            elif status == "확인 필요":
                st.warning("Evidence 조회됨 · 실행 상세 확인 필요")
            else:
                st.caption("저장 Evidence 없음")
        else:
            st.caption("시나리오 실행 후 표시됩니다.")
    if decision or execution:
        with st.expander("판정 근거 · 누적 위험 / 정책 / 실행 상태", expanded=False):
            st.write("SecurityContext · 저장된 최종 누적 위험:", decision.get("cumulative_risk_score", "기록 없음 / 재생 대기"))
            st.write("정책 버전:", decision.get("policy_version", "기록 없음 / 재생 대기"))
            st.write("실행 상태:", execution.get("execution_state", "기록 없음 / 재생 대기"))


@st.fragment(run_every=0.4)
def render_plugin_runtime(events, snapshot=None):
    config = architecture_config()
    run_id = snapshot["result"]["identity"]["run_id"] if snapshot else None
    if st.session_state.get("replay_run") != run_id:
        st.session_state["replay_run"] = run_id
        st.session_state["replay_cursor"] = len(events) - 1
        st.session_state["replay_playing"] = False
    cursor = max(-1, min(st.session_state.get("replay_cursor", len(events) - 1), len(events) - 1))
    playing = st.session_state.get("replay_playing", False)
    st.subheader("③ Guard 실행 흐름")
    st.caption("Evidence Replay · 카드는 플러그인 구조, 강조 표시는 저장 이벤트의 재생 위치입니다.")
    st.caption("저장된 Evidence를 실행 순서대로 재생합니다. 실제 Runtime은 다시 실행하지 않습니다.")
    if events:
        controls = st.columns(4)
        action = False
        if controls[0].button("▶ 자동으로 흐름 보기", key="replay_start", type="primary", width="stretch"):
            cursor, playing, action = -1, True, True
        if controls[1].button("→ 한 단계씩 보기", key="replay_next", width="stretch"):
            cursor, playing, action = min(cursor + 1, len(events) - 1), False, True
        if controls[2].button("↺ 처음부터", key="replay_reset", width="stretch"):
            cursor, playing, action = -1, False, True
        if controls[3].button("✓ 최종 결과 보기", key="replay_all", width="stretch"):
            cursor, playing, action = len(events) - 1, False, True
        if playing and not action:
            cursor = min(cursor + 1, len(events) - 1)
        if cursor >= len(events) - 1:
            playing = False
        st.progress((cursor + 1) / len(events), text="Evidence Replay")
    else:
        playing = False
    st.session_state["replay_cursor"] = cursor
    st.session_state["replay_playing"] = playing
    if events:
        st.info(replay_caption(events, cursor))
    render_pipeline(config, events, cursor)
    render_outcome(events, cursor, snapshot)
    if events:
        with st.expander("Replay 이벤트 목록 · 완료 / 현재 / 대기", expanded=False):
            st.caption("SQLite 조회 순서 그대로 재생합니다. Runtime 재실행이나 지연은 없습니다. Enforcement가 OUTPUT보다 먼저 나타날 수 있습니다.")
            st.dataframe(replay_rows(events, cursor), hide_index=True, width="stretch")
