"""Display CLI runs and their persisted Evidence without rerunning Runtime."""

import logging
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service import guard_rows, list_runs, query_events

logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="Agent Security Demo",
    page_icon="🛡️",
    layout="wide",
)
st.title("Agent Security · 실행 추적")
st.caption(
    "Runtime · Security Core · Enforcement · SQLite Evidence 통합 데모"
)
st.caption("Mock Tool 사용 · 터미널에서 실행한 결과를 조회합니다.")

with st.sidebar:
    st.header("실행 기록")
    st.button("목록 새로고침")
    runs = list_runs()
    if not runs:
        st.info("터미널에서 먼저 시나리오를 실행해주세요.")
        st.stop()
    selected = st.selectbox(
        "실행 선택",
        range(len(runs)),
        format_func=lambda i: (
            f"{runs[i]['scenario']['name']} · "
            f"{runs[i]['result']['identity']['run_id']}"
        ),
    )
    st.caption("최신 실행부터 표시합니다.")
    with st.expander("데모 정보"):
        st.write("Runtime 직접 호출 방식")
        st.write("입력과 Tool 후보는 준비된 시나리오를 사용합니다.")
        st.write("Guard 판정은 저장된 Evidence의 실제 값입니다.")
        st.write("실행 요약 JSON과 SQLite Evidence는 별도로 저장됩니다.")

snapshot = runs[selected]
result = snapshot["result"]
identity = result["identity"]
decision = result.get("decision") or {}
execution = result.get("execution") or {}

st.subheader(snapshot["scenario"]["name"])
st.code(snapshot["scenario"]["prompt"], language=None)
st.caption(f"Tool 후보: {snapshot['scenario']['tool']} / Mock 구현")

columns = st.columns(4)
columns[0].metric("최종 판정", decision.get("decision", "없음"))
columns[1].metric("Tool 호출 횟수", snapshot["tool_calls"])
columns[2].metric("출력 전달", "허용" if result["output_allowed"] else "차단")
columns[3].metric("Runtime 상태", result["run_status"])

st.code(
    f"run_id   {identity['run_id']}\n"
    f"trace_id {identity['trace_id']}",
    language=None,
)

try:
    events = query_events(identity["run_id"])
except Exception as exc:
    logger.exception("Demo operation failed")
    st.error(f"SQLite Evidence 조회 실패: {exc}")
    st.stop()

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

rows = guard_rows(events)
st.subheader("4단계 Guard 검사")
st.caption(
    "각 Guard 판정과 최종 정책 판정은 다를 수 있습니다. "
    "여러 검사 기록이 있으면 모두 표시합니다."
)
for stage, column in zip(
    ("INPUT", "CONTEXT", "TOOL", "OUTPUT"), st.columns(4)
):
    with column:
        st.markdown(f"**{stage}**")
        stage_rows = [row for row in rows if row["단계"] == stage]
        if not stage_rows:
            st.caption("검사 기록 없음")
        for row in stage_rows:
            st.write(f"{row['판정']} · {row['검사 상태']}")
            risk = row["위험 점수"]
            st.caption(
                f"위험 점수: {risk:.3f}"
                if risk is not None
                else "위험 점수: 기록 없음"
            )
st.caption(
    "기록이 없다는 사실만으로 미실행을 확정하지 않습니다. "
    "저장 오류가 있으면 아래 오류 정보도 확인해주세요."
)

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
st.dataframe(timeline, use_container_width=True, hide_index=True)

with st.expander("DB에서 조회한 Evidence JSON"):
    st.json(events)
with st.expander("Runtime 반환값 · 로컬 실행 요약"):
    st.json(result)
