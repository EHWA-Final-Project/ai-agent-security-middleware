"""Run existing demo scenarios and display persisted Evidence and reports."""

import logging
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plugin_view import render_plugin_runtime
from reports import render_evaluation
from service import list_runs, query_events, run_scenario

logger = logging.getLogger(__name__)

st.set_page_config(page_title="AI Agent Security Middleware", page_icon="🛡️", layout="wide")
st.title("AI Agent Security Middleware")
st.caption("Plugin-based Guard Runtime · Cross-layer Coordination · Enforcement · Evidence")
st.caption("Dashboard는 별도 보안 로직을 갖지 않으며, 실제 Runtime / PluginManager / Guard 실행 결과와 저장된 Evidence를 시각화합니다.")


def render_live():
    for key, label, column in zip(
        ("1", "2", "3"),
        ("🟢 정상 요청 실행", "🔴 실행 전 공격 실행", "🟠 실행 후 출력 차단 실행"),
        st.columns(3),
    ):
        if column.button(label, key=f"scenario_{key}", width="stretch"):
            try:
                with st.spinner("Runtime 실행 및 SQLite Evidence 저장 중..."):
                    latest = run_scenario(key)
                st.session_state["selected_run"] = latest["result"]["identity"]["run_id"]
            except Exception as exc:
                logger.exception("Scenario failed")
                st.error(f"Runtime 실행 실패: {exc}")

    with st.sidebar:
        st.header("실행 기록")
        st.button("목록 새로고침")
        try:
            runs = list_runs()
        except (OSError, ValueError) as exc:
            st.error(f"실행 기록 조회 실패: {exc}")
            return
        if not runs:
            st.info("Plugin Execution Trace에서 시나리오를 실행해주세요.")
        else:
            by_id = {run["result"]["identity"]["run_id"]: run for run in runs}
            if st.session_state.get("selected_run") not in by_id:
                st.session_state["selected_run"] = next(iter(by_id))
            selected = st.selectbox(
                "실행 선택", list(by_id), key="selected_run",
                format_func=lambda run_id: f"{by_id[run_id]['scenario']['name']} · {run_id}",
            )
        st.caption("최신 실행부터 표시합니다. 실행 요약과 SQLite Evidence는 별도 저장됩니다.")
    if not runs:
        render_plugin_runtime([])
        return
    snapshot = by_id[selected]
    result = snapshot["result"]
    identity = result["identity"]
    decision = result.get("decision") or {}
    execution = result.get("execution") or {}

    try:
        events = query_events(identity["run_id"])
    except Exception as exc:
        logger.exception("Demo operation failed")
        st.error(f"SQLite Evidence 조회 실패: {exc}")
        return

    render_plugin_runtime(events, snapshot)

    with st.expander("Runtime result / execution details"):
        st.subheader(snapshot["scenario"]["name"])
        st.code(snapshot["scenario"]["prompt"], language=None)
        st.caption(f"Tool 후보: {snapshot['scenario']['tool']} / Mock 구현")

        columns = st.columns(5)
        columns[0].metric("최종 판정", decision.get("decision", "없음"))
        columns[1].metric("Tool 호출 횟수", snapshot["tool_calls"])
        columns[2].metric("출력 전달", "허용" if result["output_allowed"] else "차단")
        columns[3].metric("Runtime 상태", result["run_status"])

        st.code(
            f"run_id   {identity['run_id']}\n"
            f"trace_id {identity['trace_id']}",
            language=None,
        )

        columns[4].metric("Evidence Event Count", len(events))

        id_match = bool(events) and all(
            event["run_id"] == identity["run_id"]
            and event["trace_id"] == identity["trace_id"]
            for event in events
        )
        if id_match:
            st.success(
                f"SQLite에서 Evidence {len(events)}건 조회 · run_id / trace_id 일치"
            )
        elif events:
            st.error("조회된 Evidence의 ID를 확인해야 합니다.")
        else:
            st.warning("이 실행의 Evidence가 조회되지 않았습니다.")

        left, right = st.columns(2)
        with left:
            st.subheader("실행과 출력")
            st.write("실행 상태:", execution.get("execution_state", "없음"))
            st.write("executed:", execution.get("executed"))
            if result["output_allowed"]:
                st.json(result["forward_output"])
            else:
                st.info("후속 출력 전달이 차단되었습니다.")
            with st.expander("보존된 실행 결과 · 개발자 상세"):
                st.caption("데모의 민감정보 문자열은 합성 데이터입니다.")
                st.json(execution)

        with right:
            st.subheader("최종 정책 판정")
            st.write(decision.get("reason", "판정 없음"))
            st.write("최종 누적 위험도:", decision.get("cumulative_risk_score"))
            st.write("정책:", decision.get("policy_version"))
            st.caption("Inspection mode / STRICT 전환은 Evidence에 저장되지 않아 표시하지 않습니다.")
            if result["errors"]:
                st.error("실행 중 오류가 기록되었습니다.")
                st.json(result["errors"])

    st.subheader("Evidence 타임라인")
    timeline = [
        {
            "저장 시각": event["created_at"],
            "이벤트": event["event_type"],
            "단계": event.get("stage") or "—",
            "판정 / 상태": (
                event["payload"].get("decision")
                or event["payload"].get("execution_state")
                or event["payload"].get("run_status")
                or "—"
            ),
        }
        for event in events
    ]
    st.dataframe(timeline, width="stretch", hide_index=True)

    with st.expander("DB에서 조회한 Evidence JSON"):
        st.json(events)
    with st.expander("Runtime 반환값 · 로컬 실행 요약"):
        st.json(result)


live, evaluation = st.tabs(["Plugin Execution Trace", "A/B/C Evaluation"])
with live:
    render_live()
with evaluation:
    render_evaluation()
