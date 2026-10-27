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
        }
        for index, event in enumerate(events)
    ]


def render_plugin_cards(config, visible, current=None):
    for stage, column in zip(STAGES, st.columns(4), strict=True):
        with column, st.container(border=True):
            st.markdown(f"**🧩 {stage} GUARD**")
            st.caption(f"Plugin · {stage}")
            for plugin in config["plugins"]:
                if plugin["stage"] == stage:
                    st.write(plugin["name"])
                    st.caption(f"Current code: {'ENABLED' if plugin['enabled'] else 'DISABLED'}")
            results = [e for e in visible if e["event_type"] == "SECURITY_RESULT" and e["payload"].get("stage") == stage]
            if current and current["event_type"] == "SECURITY_RESULT" and current["payload"].get("stage") == stage:
                st.info("▶ CURRENT · Stored Evidence")
            elif results:
                st.caption("✓ 완료 · 저장 결과 표시")
            if not results:
                st.caption("○ Ready · 표시 구간에 결과 기록 없음")
            for event in results:
                payload = event["payload"]
                st.caption(f"Stored Evidence · {payload.get('guard_name')}")
                show_status(payload.get("decision"), payload.get("execution_status"))
                if payload.get("risk_score") is not None:
                    st.write(f"Risk {payload['risk_score']:.3f}")
                if payload.get("latency_ms") is not None:
                    st.caption(f"{payload['latency_ms']:.3f} ms")


@st.fragment(run_every=0.4)
def render_plugin_runtime(events, snapshot=None):
    config = architecture_config()
    run_id = snapshot["result"]["identity"]["run_id"] if snapshot else None
    if st.session_state.get("replay_run") != run_id:
        st.session_state["replay_run"] = run_id
        st.session_state["replay_cursor"] = len(events) - 1
        st.session_state["replay_playing"] = False
    cursor = st.session_state.get("replay_cursor", len(events) - 1)
    playing = st.session_state.get("replay_playing", False)
    st.subheader("Plugin Architecture")
    st.caption("Architecture only · 현재 코드 구성 / 아래 Stored Evidence는 선택 run의 저장 결과")
    if snapshot:
        st.caption(f"선택 시나리오: {snapshot['scenario']['name']} · Runtime Status: {snapshot['result']['run_status']}")
    with st.container(border=True):
        st.markdown("**Runtime → Plugin Manager → Guard Plugins**")
        st.caption("Architecture only · Plugin Manager dispatch는 별도 Evidence 이벤트가 아닙니다.")
        st.caption("↓ SecurityContext / Cross-layer Coordination → SecurityDecision → Enforcement → Evidence")
    if events:
        st.markdown("**Execution Replay · Stored Evidence**")
        controls = st.columns(4)
        action = False
        if controls[0].button("▶ Replay Flow", key="replay_start"):
            cursor, playing = -1, True
            action = True
        if controls[1].button("⏭ Next Step", key="replay_next"):
            cursor, playing = min(cursor + 1, len(events) - 1), False
            action = True
        if controls[2].button("Reset Replay", key="replay_reset"):
            cursor, playing = -1, False
            action = True
        if controls[3].button("전체 결과", key="replay_all"):
            cursor, playing = len(events) - 1, False
            action = True
        if playing and not action:
            cursor = min(cursor + 1, len(events) - 1)
        if cursor >= len(events) - 1:
            playing = False
        st.caption("저장 후 visual replay · 0.4초 UI 갱신 · Runtime 재실행/지연 없음")
        st.progress((cursor + 1) / len(events), text=f"Evidence {cursor + 1} / {len(events)}")
    st.session_state["replay_cursor"] = cursor
    st.session_state["replay_playing"] = playing
    visible = events[:cursor + 1]
    current = events[cursor] if 0 <= cursor < len(events) else None
    render_plugin_cards(config, visible, current)
    with st.container(border=True):
        st.markdown("**↓ SecurityContext / Cross-layer Coordination**")
        st.caption(f"Architecture only · Current code coordination: {config['mode']} · Cross-layer Coordination: {'ON' if config['mode'] == 'linked' else 'OFF'}")
        st.caption("Linked mode에서는 앞 단계 Guard 결과가 SecurityContext에 누적되어 후속 보안 판단에 반영됩니다.")
        decisions = [event["payload"] for event in visible if event["event_type"] == "SECURITY_DECISION"]
        decision = decisions[-1] if decisions else {}
        st.write("Stored cumulative risk:", decision.get("cumulative_risk_score", "기록 없음 / pending"))
        st.write("Stored policy_version:", decision.get("policy_version", "기록 없음 / pending"))
        count = sum(e["event_type"] == "SECURITY_RESULT" for e in visible)
        st.caption(f"표시 구간 Guard result 기록: {count}건 · SecurityContext.previous_results 개수로 추론하지 않음")
        with st.expander("Configuration / Evidence 구분"):
            st.write("현재 구성은 runtime.composition.make_security_factory와 PolicyConfig에서 읽습니다. 과거 run의 Enabled / coordination 설정을 보증하는 기록이 아닙니다.")
            st.write("선택 run의 coordination mode와 inspection_mode / STRICT 전환은 Evidence에 저장되지 않아 확인 불가입니다.")
    final, enforcement = st.columns(2)
    with final, st.container(border=True):
        st.markdown("**↓ SecurityDecision**")
        show_status(decision.get("decision"))
        st.write("Cumulative risk:", decision.get("cumulative_risk_score", "—"))
        st.write("Policy:", decision.get("policy_version", "—"))
        st.caption(decision.get("reason", "Stored Evidence 대기"))
    with enforcement, st.container(border=True):
        st.markdown("**↓ Enforcement**")
        executions = [e["payload"] for e in visible if e["event_type"] == "EXECUTION_RESULT"]
        execution = executions[-1] if executions else {}
        st.write("Tool executed:", execution.get("executed", "기록 없음 / pending"))
        st.write("execution_state:", execution.get("execution_state", "—"))
        if snapshot:
            st.caption("완료된 Runtime 반환값 / 실행 요약 (Replay 진행과 별도)")
            st.write("Tool calls:", snapshot["tool_calls"])
            st.write("Output delivered:", snapshot["result"]["output_allowed"])
    with st.container(border=True):
        st.markdown("**↓ Evidence Stored · SQLite**")
        st.write("Event count:", len(events))
        if snapshot:
            identity = snapshot["result"]["identity"]
            st.code(f"run_id   {identity['run_id']}\ntrace_id {identity['trace_id']}", language=None)
            matched = bool(events) and all(e["run_id"] == identity["run_id"] and e["trace_id"] == identity["trace_id"] for e in events)
            errors = snapshot["result"].get("errors", [])
            if matched and not errors and snapshot["result"].get("run_status") == "COMPLETED":
                st.success("SQLite persistence OK · 조회된 Evidence ID 일치")
            elif events:
                st.warning("Evidence 조회됨 · ID / Runtime status / errors 상세 확인 필요")
            else:
                st.caption("저장 Evidence 없음")
        else:
            st.caption("시나리오 실행 전 · 저장 결과 없음")
    if events:
        st.caption("Replay는 SQLite 조회 순서를 따릅니다. Enforcement가 OUTPUT Guard보다 먼저 나타나는 등 실제 순서를 재정렬하지 않습니다.")
        if current:
            st.info(f"▶ CURRENT · {event_label(current)} · {event_status(current)}")
            st.caption(f"Stored Evidence · event_id: {current['event_id']}")
        with st.expander("Replay event sequence · 완료 / CURRENT / pending"):
            st.dataframe(replay_rows(events, cursor), hide_index=True, width="stretch")
