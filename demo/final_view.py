"""Academic security research console over unchanged historical observations."""

import json
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT), str(ROOT / "src"), str(ROOT / "shared")]

from actual_results import REPORT, boundary, display, load_results, rows_for
from research_ui import (
    execution_summary,
    facts,
    flow,
    heading,
    install_style,
    metrics,
    raw_details,
    readable_table,
    table,
    text,
)

st.set_page_config(page_title="GuardOn | 보안 연구 콘솔", layout="wide")
install_style()
brand, source_status = st.columns([1, 1])
with brand:
    st.title("GuardOn")
    st.html('<p class="console-kicker">보안 연구 콘솔 · Agent–MCP 실행 통제 및 근거 분석</p>')
with source_status:
    st.info("저장된 실제 실험 결과 · Qwen3:8b / MCP stdio  \n실시간 모델 실행이 아닙니다.")

PAGES = {"Overview": "실험 개요", "Actual Agent–MCP": "Agent 실행", "A/B/C/D Comparison": "A/B/C/D 비교",
         "External Benchmark": "외부 벤치마크", "Evidence / Replay": "Evidence 조사"}
SLUGS = dict(zip(PAGES, ("overview", "agent", "comparison", "benchmark", "evidence"), strict=True))
if "view_nav" not in st.session_state:
    st.session_state["view_nav"] = next((p for p in PAGES if SLUGS[p] == st.query_params.get("view")), "Overview")
page = st.radio("분석 화면", list(PAGES), key="view_nav", horizontal=True,
                format_func=PAGES.get, label_visibility="collapsed")
st.query_params["view"] = SLUGS[page]


def runtime_records():
    return json.loads((ROOT / "reports/runtime_demo/public_observations.json").read_text(encoding="utf-8"))


def select_trial(data, key):
    by_id = {row["run_id"]: row for row in data["trial_observations"]}
    selected = st.selectbox("저장된 Trial", list(by_id), key=key,
                            format_func=lambda run: f"{by_id[run]['condition']} · {by_id[run]['sample_id']} · {by_id[run]['status']}")
    return by_id[selected]


def overview(data):
    heading("실험 개요", "외부 평가와 Runtime 검증은 별도입니다. 공식 ASR·TSR·FPR은 N/A로 유지합니다.")
    config = data["configuration"]
    metrics([("외부 표본", config["mapped_samples"], "정상 6 · 공격 6"),
             ("실행 시도", config["planned_attempts"], "A/B/C/D · 단일 반복"),
             ("완료", config["status_counts"]["completed"], "실행 완료 ≠ 과제 성공"),
             ("Timeout", config["status_counts"]["timeout"], "부분 관측 보존"),
             ("Runtime 오류", config["status_counts"]["error"], "차단 성공에 미포함")])
    st.subheader("실행 구조")
    flow([("LLM Agent", "Qwen3:8b · 모델의 Tool 선택"),
          ("GuardOn", "Input / Context / Tool 검사 · 실행 후 Output 통제"),
          ("MCP Tool", "SDK tools/call · 서버 함수 진입 관측"),
          ("Evidence", "SQLite 기록 · 공개 JSON/CSV · Replay")])
    st.caption("시스템 구성도입니다. 저장된 결과를 조회하며 현재 모델·서버 연결을 뜻하지 않습니다. 허용된 Tool 출력만 후속 모델 턴으로 전달합니다.")
    left, right = st.columns([1.25, 1], gap="large")
    with left:
        st.subheader("A/B/C/D 보안 조건")
        st.html('''<table class="console-policies"><thead><tr><th scope="col">조건</th><th scope="col">정책 구성</th><th scope="col">검사 방식</th></tr></thead><tbody>
<tr><td>A</td><td>Guard OFF</td><td>보안 Guard 비활성</td></tr>
<tr><td>B</td><td>Independent Guards</td><td>각 Guard의 독립 판정</td></tr>
<tr><td>C</td><td>Linked Guards</td><td>계층 간 위험 신호 연결</td></tr>
<tr><td>D</td><td>Adaptive Inspection</td><td>FAST 시작 → 위험 시 STANDARD</td></tr>
</tbody></table>''')
        st.caption("C/D의 필수 보안 검사와 ToolPolicy를 유지합니다. PI-T01·확장 탐지 규칙은 현재 코드 기본 OFF입니다.")
    with right:
        st.subheader("Runtime 검증에서 관측한 실행 경계")
        records = runtime_records()["records"]
        chosen = [r for r in records if r["condition"] == "C" and r["category"] in {"abc_normal_preblock", "abc_postblock"}]
        entries = []
        names = {"external-normal-001": "정상 요청", "external-unauthorized-email-001": "비인가 Tool", "external-output-block-001": "위험 출력"}
        for record in chosen:
            for candidate in record["tool_executions"]:
                entries.append({"검증 사례": names.get(record["scenario_id"], record["scenario_id"]),
                                "판정": candidate["security_decision"], "SDK 호출": candidate["sdk_call_count"],
                                "모델 전달": candidate["output_delivered"]})
        readable_table(entries, alt="과거 Runtime C 조건의 정상, 실행 전 차단, 실행 후 통제 기록")
        st.caption("과거 Runtime 인계 C 조건입니다. 외부 벤치마크 48시도와 별도이며 신규 실모델 실행 결과가 아닙니다.")
    st.warning("공식 ASR / TSR / FPR: N/A · 의미 판정·최종 사용자 전달·완전한 전송 감사 등의 근거가 부족합니다.")
    with st.expander("데이터셋 · 실험 환경 · 상세 설정", expanded=False):
        facts([("BIPIA", "TableQA 5쌍 · MCP read_file 응답으로 변환"),
               ("MSB", "MCP-D01 변환 1쌍 · Tool 설명 경계"),
               ("모델 / 전송", "Qwen3:8b / MCP stdio"),
               ("관측 자료", "공개 JSON/CSV 정합성 검사 통과 · 비공개 SQLite 원본은 미포함")])
        st.json(config)
        st.caption("실험 당시 PI-T01 ON. 공개 표에 없는 candidate별 policy_version과 확장 규칙 설정은 알 수 없음입니다.")
    with st.expander("현재 코드의 정책 버전과 기본값", expanded=False):
        from security.policy.conditions import load_condition
        table([{"조건": name, "policy_version": load_condition(name).policy.policy_version,
                "PI-T01": load_condition(name).policy.output_injection_scan,
                "확장 규칙": load_condition(name).policy.extended_injection_rules} for name in "ABCD"])


def actual(data):
    heading("Agent–MCP 실행 관측", "모델 선택부터 실제 실행과 출력 전달까지, 서로 다른 경계의 관측을 확인합니다.")
    source = st.radio("실행 자료", ["Runtime 인계 · 실제 Agent", "외부 Benchmark"], horizontal=True)
    if source == "Runtime 인계 · 실제 Agent":
        runtime_replay("actual_runtime")
        return
    trial = select_trial(data, "actual_trial")
    run = trial["run_id"]
    candidates = rows_for(data, "candidate_observations", run)
    st.subheader("모델의 Tool 선택")
    table(rows_for(data, "model_tool_selections", run), ["model_turn", "tool_name", "entered_runtime", "unauthorized"])
    st.subheader("Candidate 실행 경계")
    for row in candidates:
        st.markdown(f"**{row['candidate_id']}**")
        execution_summary(row)
    st.subheader("개별 Guard 판정 근거")
    table(rows_for(data, "individual_guard_results", run), ["candidate_id", "stage", "guard_name", "decision", "rule_ids"])
    facts([("Trial 상태", trial["status"]), ("최종 사용자 전달", trial["final_user_delivery"]),
           ("Candidate trace 완전성", trial["candidate_trace_complete"])])
    st.caption("집계 판정과 개별 Guard 판정은 다릅니다. 위험도·검사 모드·tools/list 호출 수는 이 공개 관측표에 없어 알 수 없음입니다.")
    raw_details("Trial · 선택 · Candidate · Guard 원본 필드", {
        "trial": trial, "model_selection": rows_for(data, "model_tool_selections", run),
        "candidates": candidates, "guards": rows_for(data, "individual_guard_results", run)})


def comparison(data):
    heading("A/B/C/D 조건 비교", "동일 표본의 상태·차단 경계·실행·전달을 나누어 비교합니다.")
    sample = st.selectbox("동일 표본", sorted({r["sample_id"] for r in data["trial_observations"]}), key="compare_sample")
    trials = [t for t in data["trial_observations"] if t["sample_id"] == sample]
    candidates = [r for r in data["candidate_observations"] if r["sample_id"] == sample]
    st.subheader("조건별 실행 결과")
    readable_table(trials, ["condition", "classification", "status", "candidate_count", "tool_sdk_calls", "unauthorized_selection", "unauthorized_execution"], alt="같은 표본의 A/B/C/D 실행 상태 비교")
    st.subheader("Tool 실행과 출력 통제")
    table([{"boundary": boundary(r), **r} for r in candidates],
          ["condition", "candidate_id", "tool_name", "aggregate_decision", "boundary", "toolpolicy_denial", "output_guard_block", "output_delivered"])
    st.caption("ToolPolicy 차단은 Injection 탐지 성공률이 아닙니다. output_delivered는 모델 전달이며 최종 사용자 전달과 다릅니다.")
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.subheader("C와 Adaptive D")
        flow([("C", "STANDARD 검사 · 계층 연결"), ("D 시작", "FAST 검사"),
              ("위험 신호", "STANDARD 승격"), ("필수 통제", "동일한 Guard·ToolPolicy 유지")])
    with right:
        st.subheader("비교 범위")
        match = next(r for r in data["matched_abcd_comparisons"] if r["sample_id"] == sample)
        facts([("4조건 시도 존재", match["all_four_attempts_present"]),
               ("4조건 모두 완료", match["all_four_completed"]),
               ("미완료 조건", match["missing_completed_conditions"])])
    st.warning("Timeout·오류를 차단 성공으로 세지 않습니다. 모델 선택과 완료 표본이 달라 C/D 성능·Latency 우열을 추론할 수 없습니다.")
    raw_details("정책 설정 · 비교 완전성 · 원본 관측", {"pi_t01": data["configuration"]["configuration"]["pi_t01"],
                "historical_candidate_policy_version": None, "historical_extended_injection_rules": None,
                "historical_inspection_mode": None, "matched": match, "trials": trials, "candidates": candidates})


GRAPHS = [
    ("실행 상태", "dashboard/graphs/execution_status.png", "조건별 완료·Timeout·오류"),
    ("실행 경계", "dashboard/graphs/operational_boundaries.png", "Tool 실행과 출력 전달 경계"),
    ("비인가 Tool", "dashboard/graphs/unauthorized_tool_observations.png", "비인가 Tool의 선택과 실행"),
    ("응답 분석", "dashboard/graphs/generated_response_findings.png", "생성 응답의 사후 분석 범위"),
    ("Latency", "latency/backend_latency.png", "Backend Latency (s) · LLM 포함 · 완료 표본만"),
]


def benchmark(data):
    heading("외부 벤치마크 평가", "BIPIA·MSB의 일부 변환 표본에 대한 단일 반복 관측입니다. 공식 Benchmark 전체 점수가 아닙니다.")
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.subheader("조건별 실행 상태")
        counts = pd.DataFrame(data["trial_observations"]).groupby(["condition", "status"]).size().unstack(fill_value=0)
        chart = counts.rename(columns={"completed": "완료", "timeout": "Timeout", "error": "오류"})
        plot_data = chart.reset_index().melt("condition", var_name="상태", value_name="시도 수")
        plot = alt.Chart(plot_data).mark_bar().encode(
            x=alt.X("condition:N", title="조건", axis=alt.Axis(labelAngle=0)),
            xOffset="상태:N", y=alt.Y("시도 수:Q", title="시도 수"),
            color=alt.Color("상태:N", scale=alt.Scale(domain=["완료", "Timeout", "오류"], range=["#0B6B66", "#A36A13", "#A32D3D"]), legend=alt.Legend(orient="top", title=None)),
            tooltip=["condition:N", "상태:N", "시도 수:Q"],
        ).properties(height=230, description="조건별 완료·Timeout·오류의 실제 시도 수").configure_axis(labelFontSize=13, titleFontSize=14).configure_legend(labelFontSize=13)
        st.altair_chart(plot, width="stretch")
        readable_table(chart.reset_index().to_dict("records"), alt="조건별 완료, Timeout, 오류의 실제 시도 수")
    with right:
        st.subheader("표본과 출처")
        facts([("BIPIA TableQA", "5쌍 · 원본 질문·공격 보존 · Tool 응답으로 변환"),
               ("MSB 기반 MCP-D01", "1쌍 · Tool 설명으로 변환"),
               ("평가 구성", "정상 6 / 공격 6 · 총 12표본 × 4조건"),
               ("실행 환경", "Qwen3:8b · PI-T01 ON · 단일 반복"),
               ("해석 범위", "관측 기반 기술통계 · 인과적 방어 효과 아님")])
        with st.expander("원본 출처 · 라이선스 · 변환 · 해시"):
            manifest = json.loads((ROOT / "benchmarks/mcp_external_manifest.json").read_text(encoding="utf-8"))
            for sample in manifest["samples"]:
                st.markdown(f"**{sample['sample_id']}**")
                st.json({"provenance": sample["provenance"], "transformation": sample.get("transformation"), "mapped_case_sha256": sample["mapped_case_sha256"]})
            st.caption("이 manifest는 매핑 단계의 상태입니다. 실제 실행 여부는 Trial 관측표를 사용합니다.")
    st.subheader("관측 지표")
    filters = st.columns([2, 1])
    scopes = sorted({r["scope"] for r in data["operational_metrics"]})
    with filters[0]:
        scope = st.selectbox("관측 범위", scopes, index=scopes.index("completed_trials_primary"),
                             format_func=lambda s: {"completed_trials_primary": "완료 Trial · 주요 관측", "all_saved_attempts_diagnostic": "전체 저장 시도 · 부분 관측 포함"}.get(s, s))
    with filters[1]:
        condition = st.selectbox("지표 조건", ["ALL", "A", "B", "C", "D"])
    for name, title in [("operational_metrics", "실행·전달 관측"), ("semantic_metrics", "의미 기반 사후 분석")]:
        st.markdown(f"**{title}**")
        rows = [r for r in data[name] if r["scope"] == scope and r["condition"] == condition and r["dataset"] == "ALL"]
        table(rows, ["metric", "numerator", "denominator", "denominator_unit", "sample_coverage", "excluded_or_unknown_count"], alt=f"{title}의 분자와 분모")
        raw_details(f"{title} · 비율·제외 사유·전체 필드", rows)
    st.warning("공식 ASR / TSR / FPR: N/A · 적격 분모 0의 rate=null은 0%가 아닙니다. ToolPolicy 차단과 Injection 탐지, 출력 미전달과 개별 Output Guard BLOCK을 구분합니다.")
    raw_details("공식 지표 N/A 사유 · 지표 정의", {"formal": data["report_summary_ko"]["공식지표"], "definitions": data["metric_definitions"]})
    st.subheader("저장된 실제 실험 그래프 5종")
    for tab, (_, path, caption) in zip(st.tabs([g[0] for g in GRAPHS]), GRAPHS, strict=True):
        with tab:
            image = REPORT / path
            if image.is_file():
                st.image(str(image), caption=caption, alt=caption, width="stretch")
            else:
                st.error(f"그래프 파일 없음: {path}. 저장소의 평가 산출물을 확인하세요.")
    st.caption("Security Core Latency(ms)와 LLM 포함 Backend Latency(s)는 다릅니다. 별도 Core 실험의 약 31.5% 감소를 전체 Agent 속도 개선으로 해석하지 않습니다.")
    st.download_button("Trial 관측 CSV 다운로드", (REPORT / "dashboard/trial_observations.csv").read_bytes(), "trial_observations.csv", "text/csv")


def replay(data):
    heading("Evidence / Trace 조사", "실행 사실과 보안 판단을 확인합니다. Replay는 모델이나 Tool을 다시 호출하지 않습니다.")
    source = st.radio("Replay 자료", ["외부 Benchmark", "Runtime 인계 · 실제 Agent"], horizontal=True)
    if source == "Runtime 인계 · 실제 Agent":
        runtime_replay("replay_runtime")
        return
    trial = select_trial(data, "replay_trial")
    run = trial["run_id"]
    candidates = rows_for(data, "candidate_observations", run)
    if candidates:
        index = st.select_slider("Candidate 순서", range(1, len(candidates) + 1))
        row = candidates[index - 1]
        execution_summary(row)
        st.subheader(f"{row['candidate_id']} · Guard 판단 근거")
        table([g for g in rows_for(data, "individual_guard_results", run) if g["candidate_id"] == row["candidate_id"]],
              ["stage", "guard_name", "decision", "rule_ids", "evidence_id"])
        table([row], ["candidate_id", "tool_name", "aggregate_decision", "sdk_call_count", "server_tool_execution_count", "output_allowed", "output_delivered"])
    else:
        st.warning("Runtime Candidate 기록 없음. Agent 실행 화면에서 모델 선택 기록과 오류/Timeout을 확인하세요.")
    raw_details("Trial · Trace · Runtime · Evidence 식별자와 원본 기록", {"trial": trial, "candidates": candidates,
                "model_selections": rows_for(data, "model_tool_selections", run), "guards": rows_for(data, "individual_guard_results", run)})
    st.caption("Evidence ID는 원본 연결 식별자입니다. 공개 JSON 조회는 비공개 SQLite 원본 재감사를 뜻하지 않습니다. 기록이 없으면 알 수 없음으로 표시합니다.")
    with st.expander("기존 로컬 SQLite Replay · Fixture/Mock 실행 자료"):
        from plugin_view import render_plugin_runtime
        from service import list_runs, query_events
        runs = list_runs()
        if runs:
            by_run = {r["result"]["identity"]["run_id"]: r for r in runs}
            selected = st.selectbox("Fixture/Mock run", list(by_run), key="local_replay_run")
            render_plugin_runtime(query_events(selected), by_run[selected])
        else:
            st.caption("로컬 기록 없음. 기존 Workbench에서 합성 시나리오를 실행하면 SQLite Replay가 가능합니다.")
        st.caption("Fixture/Mock 자료는 실제 LLM 벤치마크와 합산하지 않습니다.")


def runtime_replay(key):
    try:
        handoff = runtime_records()
    except (OSError, ValueError):
        st.error("Runtime 공개 인계 관측 파일을 읽을 수 없습니다. reports/runtime_demo/public_observations.json을 확인하세요.")
        return
    records = handoff["records"]
    categories = {"abcd_multistep": "정상 다단계", "abc_normal_preblock": "정상·실행 전 차단", "abc_postblock": "실행 후 출력 통제", "d_boundary": "Adaptive D 경계"}
    index = st.selectbox("Runtime 인계 기록", range(len(records)), key=key,
                         index=next(i for i, r in enumerate(records) if r["category"] == "abcd_multistep" and r["condition"] == "C"),
                         format_func=lambda i: f"{records[i]['condition']} · {categories.get(records[i]['category'], records[i]['category'])} · {records[i]['scenario_id']}")
    record = records[index]
    st.caption(f"{record['policy_version']} · PI-T01 {'ON' if record['output_injection_scan'] else 'OFF' if record['output_injection_scan'] is False else '알 수 없음'} · 초기 검사 {display(record['initial_inspection_mode'])} · 상태 {record['run_status']}")
    executions = record["tool_executions"] or []
    if executions:
        step = st.select_slider("Runtime Candidate 순서", range(1, len(executions) + 1), key=f"{key}_step")
        execution_summary(executions[step - 1], runtime=True)
        st.subheader("Candidate별 실행과 전달 경계")
        table(executions[:step], ["candidate_id", "model_turn", "tool_name", "security_decision", "execution_state", "sdk_call_count", "output_allowed", "output_delivered"])
    else:
        st.info("Runtime Candidate 기록 없음 · 아래 모델 턴과 오류 상태를 확인하세요.")
    left, right = st.columns([1, 1.2], gap="large")
    with left:
        st.subheader("모델 턴")
        table(record["model_turns"] or [], ["turn", "model", "tool_call_count", "finish_reason"])
    with right:
        st.subheader("실제 SDK 호출")
        table(record["sdk_calls"] or [], ["method", "candidate_id", "tool_name", "invoked"])
    facts([("최종 응답 관측", record["final_response_observed"]),
           ("최종 사용자 전달", record["final_response_delivered_to_user"]),
           ("Timeout", record["timed_out"]), ("Runtime 오류 종류", record["error_type"]),
           ("Guard trace 완전성", record["guard_trace_complete"])])
    raw_details("정책 · Run/Trace · Evidence ID · SDK 시각 · 원본 필드", record)
    st.caption("최종 집계 판정은 개별 Guard 판정과 다릅니다. 이 요약에 없는 위험도·triggered_rules는 알 수 없음입니다. SDK 진입과 서버 실행은 별도 관측이며 mcp_call_id=null을 보존합니다.")
    st.caption("저장된 실제 Runtime 검증 29 Agent 기록(Timeout 주입 포함). 별도 고정 후보 실제 MCP 검증 16건 및 외부 Benchmark 48시도와 합산하지 않습니다. 과거 구현 단계별 기록이며 최종 SHA 재실행 결과가 아닙니다.")


try:
    data = load_results()
except (OSError, ValueError, KeyError, TypeError) as exc:
    st.error(f"실험 결과 정합성 검사 실패: {type(exc).__name__}: {exc}. 원본 평가 산출물을 확인하세요.")
    st.stop()

{"Overview": overview, "Actual Agent–MCP": actual, "A/B/C/D Comparison": comparison,
 "External Benchmark": benchmark, "Evidence / Replay": replay}[page](data)
st.divider()
st.page_link("dashboard.py", label="기존 Workbench 열기 · Fixture/Mock 자료")
st.html(f'<p class="console-note">{text("공개 관측 자료 기반 · 원본 실험 기록과 정책은 변경하지 않았습니다. unknown / N/A는 0이 아닙니다.")}</p>')
