"""Scenario-first product demo over the existing Runtime and SQLite Evidence."""

import logging
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from plugin_view import evidence_status, render_plugin_runtime
from reports import render_evaluation
from service import list_runs, query_events, run_scenario
from workbench import render_attack_catalog, render_benchmark_lab

logger = logging.getLogger(__name__)

SCENARIO_CARDS = (
    ("1", "🟢", "정상 요청", "안전한 문서를 읽고 결과를 사용자에게 전달합니다.", "ALLOW / Tool 실행 / Output 전달"),
    ("2", "🔴", "공격 시도 차단", "보안 지침을 우회하려는 입력을 실행 전에 차단합니다.", "BLOCK / Tool 미실행"),
    ("3", "🟠", "실행 후 출력 차단", "Tool 결과에 포함된 민감정보가 사용자에게 전달되지 않도록 막습니다.", "BLOCK / Tool 실행됨 / 사용자 출력 차단"),
)

st.set_page_config(page_title="AI Agent Security Middleware", page_icon="🧩", layout="wide")
st.html("""<style>
    .stMainBlockContainer { max-width: 1280px; padding-top: 2.4rem; }
    [data-testid="stMetricValue"] { font-size: 1.85rem; }
    [data-testid="stVerticalBlockBorderWrapper"] { border-radius: 16px; }
    div[data-testid="stButton"] button { border-radius: 10px; }
</style>""")
st.caption("AI Agent Security Middleware")
st.title("플러그인으로 지키는 Agent 실행")
st.markdown("**Plugin-based Guard Runtime Demo** · Cross-layer Coordination · Evidence Replay")
st.caption("시나리오를 실행하고, Guard 판단이 실제 실행과 출력 전달에 어떻게 연결되는지 확인하세요.")


def render_scenarios():
    st.subheader("① 시나리오를 선택하세요")
    for (key, icon, title, description, expected), column in zip(SCENARIO_CARDS, st.columns(3), strict=True):
        with column, st.container(border=True):
            st.markdown(f"### {icon} {title}")
            st.write(description)
            st.caption("예상 결과 · 실행 결과는 아래에서 확인")
            st.markdown(f"**{expected}**")
            if st.button("실행", key=f"scenario_{key}", type="primary", width="stretch", help=f"{title} 시나리오 실행"):
                try:
                    with st.spinner("② 실제 Runtime 실행 · Evidence 저장 중…"):
                        latest = run_scenario(key)
                    st.session_state["selected_run"] = latest["result"]["identity"]["run_id"]
                except Exception as exc:
                    logger.exception("Scenario failed")
                    st.error(f"Runtime 실행 실패: {exc}")


def render_summary(snapshot, events):
    result = snapshot["result"]
    decision = result.get("decision") or {}
    execution = result.get("execution") or {}
    executed = execution.get("executed")
    labels = (
        ("최종 판정", decision.get("decision") or "기록 없음"),
        ("Tool 실행 여부", "실행됨" if executed is True else "미실행" if executed is False else "기록 없음"),
        ("Output 전달 여부", "전달" if result["output_allowed"] else "차단"),
        ("Evidence 저장 여부", evidence_status(events, snapshot)),
    )
    st.subheader("이번 실행의 결과")
    st.caption(f"{snapshot['scenario']['name']} · 완료된 Runtime 결과 / Replay 진행과 별도")
    for (label, value), column in zip(labels, st.columns(4), strict=True):
        with column, st.container(border=True):
            st.metric(label, value)
    st.caption(f"Tool 호출 {snapshot['tool_calls']}회 · Evidence {len(events)}건 · 완료된 Runtime: {result['run_status']}")
    identity = result["identity"]
    st.caption(f"run_id: {identity['run_id']} · trace_id: {identity['trace_id']}")
    if decision.get("decision") == "WARN":
        st.warning("WARN은 경고 판정입니다. 실제 Tool 실행과 출력 전달 여부는 위 Runtime 결과를 확인하세요.")
    elif decision.get("decision") == "BLOCK":
        if executed is True:
            st.info("Tool 실행 이후 출력 전달이 차단되었습니다. 이미 실행된 Tool을 되돌리는 것은 아닙니다.")
        elif executed is False and snapshot["tool_calls"] == 0:
            st.info("실행 전 차단: 실제 Tool 호출 0회입니다.")
    if result.get("errors"):
        st.warning("실행 중 오류가 기록되었습니다. 아래 실행 상세를 확인하세요.")


def render_live():
    with st.container(border=True):
        st.markdown("① 시나리오 선택 → ② 실행 → 최종 결과 확인 → ③ Guard Replay → ⑤ Evidence 확인")
    render_scenarios()

    # History stays available, without reserving a sidebar or leading the demo.
    with st.expander("이전 실행 불러오기", expanded=False):
        st.button("기록 새로고침")
        try:
            runs = list_runs()
        except (OSError, ValueError) as exc:
            st.error(f"실행 기록 조회 실패: {exc}")
            return
        if runs:
            by_id = {run["result"]["identity"]["run_id"]: run for run in runs}
            if st.session_state.get("selected_run") not in by_id:
                st.session_state["selected_run"] = next(iter(by_id))
            selected = st.selectbox(
                "실행 선택", list(by_id), key="selected_run",
                format_func=lambda run_id: f"{by_id[run_id]['scenario']['name']} · {by_id[run_id]['created_at']} · {run_id}",
            )
        else:
            st.caption("아직 실행 기록이 없습니다. 위 카드에서 시작하세요.")
    if not runs:
        st.info("위에서 시나리오를 실행하면 실제 결과와 저장된 Evidence Replay가 여기에 표시됩니다.")
        render_plugin_runtime([])
        return

    snapshot = by_id[selected]
    result = snapshot["result"]
    identity = result["identity"]
    try:
        events = query_events(identity["run_id"])
    except Exception as exc:
        logger.exception("Evidence query failed")
        st.error(f"SQLite Evidence 조회 실패: {exc}")
        return
    render_summary(snapshot, events)
    render_plugin_runtime(events, snapshot)

    st.subheader("⑤ 저장된 Evidence 확인")
    st.caption(f"SQLite에서 읽은 {len(events)}개 이벤트 · 실행 순서와 원본 데이터")
    with st.expander("Evidence 타임라인", expanded=False):
        st.dataframe([
            {
                "저장 시각": event["created_at"], "이벤트": event["event_type"],
                "단계": event.get("stage") or "—",
                "판정 / 상태": event["payload"].get("decision") or event["payload"].get("execution_state") or event["payload"].get("run_status") or "—",
            }
            for event in events
        ], width="stretch", hide_index=True)
    with st.expander("실행 상세 · 정책 / 출력 / 식별자", expanded=False):
        st.write("시나리오:", snapshot["scenario"]["name"])
        st.code(snapshot["scenario"]["prompt"], language=None)
        st.write("최종 정책 판정:", result.get("decision"))
        st.write("실행 결과:", result.get("execution"))
        st.code(f"run_id   {identity['run_id']}\ntrace_id {identity['trace_id']}", language=None)
        if result["output_allowed"]:
            st.write("사용자에게 전달된 출력")
            st.json(result["forward_output"])
        else:
            st.info("사용자 출력 전달이 차단되었습니다.")
        if result.get("errors"):
            st.json(result["errors"])
    with st.expander("DB에서 조회한 Evidence JSON", expanded=False):
        st.json(events)
    with st.expander("Runtime 반환값 · 로컬 실행 요약", expanded=False):
        st.json(result)


live, evaluation, attacks, benchmark = st.tabs([
    "Plugin Execution Trace", "A/B/C Evaluation", "Attack Playground", "Benchmark Lab",
])
with live:
    render_live()
with evaluation:
    render_evaluation()
with attacks:
    render_attack_catalog()
with benchmark:
    render_benchmark_lab()
