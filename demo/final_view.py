"""Final GuardOn dashboard using recorded actual experiments and existing replay."""

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "demo"), str(ROOT), str(ROOT / "src"), str(ROOT / "shared")]

from actual_results import REPORT, boundary, display, load_results, rows_for

st.set_page_config(page_title="GuardOn | Security Analysis", layout="wide")
st.html("""<style>
.stMainBlockContainer {max-width:1480px;padding-top:2rem}
[data-testid="stMetricValue"] {font-size:1.8rem}
h1,h2,h3 {letter-spacing:-.02em}
</style>""")
st.title("GuardOn")
st.caption("Agent–MCP Security Analysis · Input / Context / Tool / Output · Evidence Replay")
st.info("저장된 실제 실험 결과 · Qwen3:8b / MCP stdio · 실시간 모델 실행이 아닙니다.")
page = st.radio("분석 화면", ["Overview", "Actual Agent–MCP", "A/B/C/D Comparison",
                         "External Benchmark", "Evidence / Replay"], horizontal=True)


def table(rows, columns=None):
    if not rows:
        st.info("기록 없음 · 알 수 없음")
        return
    if columns:
        rows = [{key: row.get(key) for key in columns} for row in rows]
    st.dataframe(pd.DataFrame([{k: str(display(v)) for k, v in row.items()} for row in rows]),
                 width="stretch", hide_index=True)


def select_trial(data, key):
    trials = data["trial_observations"]
    by_id = {row["run_id"]: row for row in trials}
    selected = st.selectbox("저장된 Trial", list(by_id), key=key,
                            format_func=lambda run: f"{by_id[run]['condition']} · {by_id[run]['sample_id']} · {by_id[run]['status']}")
    return by_id[selected]


def overview(data):
    config = data["configuration"]
    for col, (label, value) in zip(st.columns(5), [
        ("변환 표본", config["mapped_samples"]), ("시도", config["planned_attempts"]),
        ("완료", config["status_counts"]["completed"]), ("Timeout", config["status_counts"]["timeout"]),
        ("Runtime 오류", config["status_counts"]["error"])], strict=True):
        col.metric(label, value)
    st.subheader("실행 아키텍처와 연결 상태")
    st.code("LLM tool selection → MCP description (untrusted Context)\n"
            "→ Input / Context / Tool Guard → ToolPolicy → MCP SDK tools/call\n"
            "→ Server tool → Output Guard → permitted output → next model turn\n"
            "                ↘ SQLite Evidence → Evaluation → Dashboard Replay", language=None)
    table([
        {"연결": "저장된 실제 LLM–MCP 관측", "상태": "JSON/CSV 로딩 및 식별자 검사 통과"},
        {"연결": "원본 SQLite / 모델 응답", "상태": "공개 번들에 미포함 · 원본 재감사와 구분"},
        {"연결": "현재 LLM / MCP 서버", "상태": "연결 확인 안 함 · Replay는 서버를 호출하지 않음"},
    ])
    st.subheader("조건과 현재 코드 설정")
    from security.policy.conditions import load_condition
    table([{"조건": name, "방식": description,
            "기본 policy_version": load_condition(name).policy.policy_version,
            "PI-T01 기본": load_condition(name).policy.output_injection_scan,
            "확장 규칙 기본": load_condition(name).policy.extended_injection_rules}
           for name, description in [("A", "Guard OFF"), ("B", "Independent Guards"),
                                     ("C", "Linked Guards"), ("D", "FAST → 위험 신호 시 STANDARD")]])
    st.warning("공식 ASR / TSR / FPR: N/A · 소규모 12표본 × 4조건, 단일 반복. 완료는 과제 성공을 뜻하지 않습니다.")
    st.subheader("저장된 실험의 설정과 출처")
    st.json(config)
    st.caption("실험 당시 PI-T01 ON. 확장 규칙과 candidate별 policy_version은 이 공개 관측표에 없으므로 알 수 없음. 현재 코드 기본값으로 과거 설정을 대체하지 않습니다.")


def actual(data):
    source = st.radio("실행 자료", ["Runtime 인계 · 실제 Agent", "외부 Benchmark"], horizontal=True)
    if source == "Runtime 인계 · 실제 Agent":
        runtime_replay("actual_runtime")
        return
    trial = select_trial(data, "actual_trial")
    run = trial["run_id"]
    st.subheader("모델이 선택한 Tool과 Runtime 진입")
    table(rows_for(data, "model_tool_selections", run))
    st.subheader("Candidate 실행 경계")
    candidates = rows_for(data, "candidate_observations", run)
    table([{"boundary": boundary(row), **row} for row in candidates])
    st.subheader("개별 Guard 근거")
    table(rows_for(data, "individual_guard_results", run))
    st.caption("aggregate_decision은 전체 정책 판정입니다. 개별 Guard의 실행 전/후 판정은 stage와 rule_ids로 확인합니다. 공개 표에 위험도 점수·검사 모드·정확한 SDK 호출 시각이 없어 알 수 없음입니다.")
    st.subheader("Trial 상태 및 전달 관측")
    table([trial])
    st.caption("output_delivered는 반환된 후속 모델 턴으로 전달한 관측입니다. final_user_delivery=null은 최종 사용자 전달 미확인입니다. tools/list 호출 수는 이 표에 없습니다.")


def comparison(data):
    sample = st.selectbox("동일 표본", sorted({r["sample_id"] for r in data["trial_observations"]}), key="compare_sample")
    trials = [t for t in data["trial_observations"] if t["sample_id"] == sample]
    table(trials, ["sample_id", "classification", "dataset", "condition", "status", "candidate_count",
                   "tool_sdk_calls", "unauthorized_selection", "unauthorized_execution", "backend_latency_ms"])
    table([{"boundary": boundary(row), **row} for row in data["candidate_observations"] if row["sample_id"] == sample],
          ["condition", "candidate_id", "tool_name", "aggregate_decision", "boundary", "toolpolicy_denial",
           "output_guard_block", "sdk_call_count", "server_tool_execution_count", "output_allowed", "output_delivered"])
    st.subheader("비교 완전성")
    table([r for r in data["matched_abcd_comparisons"] if r["sample_id"] == sample])
    st.caption("부분 Timeout/오류를 차단 성공으로 세지 않습니다. 모델 선택과 완료 표본 차이가 있어 C/D 방어 성능이나 Latency 우열을 추론할 수 없습니다.")
    st.info("Adaptive D는 현재 코드에서 FAST로 시작해 위험 신호에 STANDARD로 승격합니다. 과거 Trial별 검사 모드와 policy_version은 공개 결과에서 알 수 없음입니다. PI-T01 ON은 experiment_configuration.json에 기록되어 있습니다.")


def benchmark(data):
    st.subheader("외부 데이터 출처와 변환")
    st.markdown("BIPIA TableQA 5쌍 + MSB 기반 MCP-D01 변환 1쌍: 정상 6 / 공격 6. 원본 Benchmark 전체 평가가 아닌 MCP 환경 변환 표본입니다.")
    manifest = json.loads((ROOT / "benchmarks/mcp_external_manifest.json").read_text(encoding="utf-8"))
    provenance = []
    for sample in manifest["samples"]:
        source = sample["provenance"]
        provenance.append({"sample_id": sample["sample_id"], "dataset": sample["dataset_id"],
                           "source_url": source["source_url"], "revision": source["revision"],
                           "context_license": source.get("context_license", source.get("license_spdx")),
                           "attack_license": source.get("attack_license", source.get("license_spdx")),
                           "transformation": sample.get("transformation"),
                           "mapped_case_sha256": sample["mapped_case_sha256"]})
    with st.expander("표본 출처 · 라이선스 · 변환 · 해시"):
        table(provenance)
    st.caption("benchmarks/mcp_external_manifest.json은 mapping 단계 manifest입니다. 실제 실행 여부는 저장된 Trial 관측표를 사용합니다.")
    counts = pd.DataFrame(data["trial_observations"]).groupby(["condition", "status"]).size().unstack(fill_value=0)
    st.bar_chart(counts, stack=False)
    table(counts.reset_index().to_dict("records"))
    st.subheader("관측 지표 · 분자 / 분모 / 제외 사유")
    scope = st.selectbox("관측 범위", sorted({r["scope"] for r in data["operational_metrics"]}))
    condition = st.selectbox("지표 조건", ["ALL", "A", "B", "C", "D"])
    for name, title in [("operational_metrics", "운영 관측"), ("semantic_metrics", "의미 기반 사후 분석")]:
        st.markdown(f"**{title}**")
        table([r for r in data[name] if r["scope"] == scope and r["condition"] == condition and r["dataset"] == "ALL"])
    st.subheader("공식 지표 · N/A 사유")
    st.json(data["report_summary_ko"]["공식지표"])
    st.warning("적격 분모 0의 rate=null은 N/A입니다. ToolPolicy 차단을 Injection 탐지 성공률로 표시하지 않습니다. Output 미전달은 개별 Output Guard BLOCK과 구분합니다.")
    with st.expander("지표 정의"):
        st.json(data["metric_definitions"])
    st.subheader("저장된 실제 실험 그래프 5종")
    for path, caption in [
        ("dashboard/graphs/execution_status.png", "조건별 완료 / Timeout / 오류"),
        ("dashboard/graphs/operational_boundaries.png", "실행과 출력 전달 경계"),
        ("dashboard/graphs/unauthorized_tool_observations.png", "비인가 Tool 선택과 실행"),
        ("dashboard/graphs/generated_response_findings.png", "생성 응답의 사후 분석 범위"),
        ("latency/backend_latency.png", "Backend Latency (s) · LLM 포함 · 완료 표본만")]:
        image = REPORT / path
        if image.is_file():
            st.image(str(image), caption=caption, width="stretch")
        else:
            st.error(f"그래프 파일 없음: {path}")
    st.caption("Security Core 단독 Latency(ms)와 Backend Latency(s)는 다릅니다. 별도 Core 실험의 약 31.5% 감소를 전체 Agent 속도 개선으로 해석하지 않습니다.")
    st.download_button("Trial 관측 CSV", (REPORT / "dashboard/trial_observations.csv").read_bytes(), "trial_observations.csv", "text/csv")


def replay(data):
    source = st.radio("Replay 자료", ["외부 Benchmark", "Runtime 인계 · 실제 Agent"], horizontal=True)
    if source == "Runtime 인계 · 실제 Agent":
        runtime_replay("replay_runtime")
        return
    trial = select_trial(data, "replay_trial")
    run = trial["run_id"]
    st.code(f"run_id: {run}\ntrace_id: {trial['trace_id']}", language=None)
    candidates = rows_for(data, "candidate_observations", run)
    if candidates:
        index = st.select_slider("Candidate 순서", range(1, len(candidates) + 1))
        row = candidates[index - 1]
        st.subheader(f"{row['candidate_id']} · {boundary(row)}")
        table([row])
        table([g for g in rows_for(data, "individual_guard_results", run) if g["candidate_id"] == row["candidate_id"]])
        st.caption("Evidence ID는 원본 연결 식별자이며, 공개 JSON 로딩은 비공개 SQLite 원본 재검증을 뜻하지 않습니다. 저장된 후보 순서만 재생하며 실행을 호출하지 않습니다.")
    else:
        st.warning("Runtime Candidate 기록 없음 · 모델 선택 기록과 오류/Timeout을 Actual 화면에서 확인하세요.")
    st.info("실행 전 BLOCK: SDK/서버 호출 0. 실행 후 미전달: 실행 사실을 보존하고 모델 전달 여부를 별도로 확인. EXECUTED와 최종 BLOCK은 함께 발생할 수 있습니다.")
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
        st.caption("이 자료는 실제 LLM 벤치마크와 합산하지 않습니다.")


def runtime_replay(key):
    path = ROOT / "reports/runtime_demo/public_observations.json"
    if not path.is_file():
        st.error("Runtime 공개 인계 관측 파일 없음")
        return
    handoff = json.loads(path.read_text(encoding="utf-8"))
    records = handoff["records"]
    index = st.selectbox("Runtime 인계 기록", range(len(records)), key=key,
                         format_func=lambda i: f"{records[i]['category']} · {records[i]['condition']} · {records[i]['scenario_id']}")
    record = records[index]
    st.caption("저장된 실제 Runtime 기능 검증 · 외부 Benchmark 48시도와 별도 집계. 과거 구현 단계별 기록이며 최종 SHA 재실행 결과가 아닙니다.")
    table([{k: v for k, v in record.items() if k not in {"model_turns", "sdk_calls", "tool_executions"}}])
    st.subheader("모델 턴과 실제 SDK 호출")
    table(record["model_turns"] or [])
    table(record["sdk_calls"] or [])
    st.subheader("Candidate별 실행과 전달 경계")
    executions = record["tool_executions"] or []
    if executions:
        step = st.select_slider("Runtime Candidate 순서", range(1, len(executions) + 1), key=f"{key}_step")
        table(executions[:step])
        selected = executions[step - 1]
        if selected["tool_executed"] is True and selected["security_decision"] == "BLOCK":
            st.info("EXECUTED + 최종 BLOCK · Tool은 실행되었고 출력은 별도 통제되었습니다.")
    st.caption("security_decision은 최종 집계 판정입니다. 원본 Guard별 위험도/triggered_rules는 이 공개 요약에 없어 알 수 없음입니다. SDK 호출과 서버 진입은 별도 관측이며 mcp_call_id=null을 보존합니다.")
    st.caption("29 Agent 기록(Timeout 주입 검증 포함), 별도 고정 후보 실제 MCP 검증 16건. 최종 사용자 전달/의미적 성공은 확립되지 않았습니다. 원문·Tool 인자·비공개 SQLite는 포함하지 않습니다.")


try:
    data = load_results()
except (OSError, ValueError, KeyError, TypeError) as exc:
    st.error(f"실험 결과 로딩/정합성 검사 실패: {type(exc).__name__}: {exc}")
    st.stop()

{"Overview": overview, "Actual Agent–MCP": actual, "A/B/C/D Comparison": comparison,
 "External Benchmark": benchmark, "Evidence / Replay": replay}[page](data)
st.divider()
st.caption("기존 Workbench / Fixture 시연 / SQLite Replay")
st.page_link("dashboard.py", label="기존 Dashboard와 Workbench 열기")
