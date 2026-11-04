"""UI-only contest guidance; no new execution or benchmark contracts."""

import logging

import streamlit as st

logger = logging.getLogger(__name__)

ATTACKS = (
    (
        "PI-D01",
        "Direct Prompt Injection",
        "Input",
        "지침 우회",
        "카드 2 · 내부 합성 대표 예시",
    ),
    (
        "PI-I01",
        "Indirect Prompt Injection",
        "Context",
        "외부 문맥으로 실행 유도",
        "준비 중 / 후속 검증",
    ),
    (
        "PI-T01",
        "Tool Response Injection",
        "Tool",
        "도구 응답으로 후속 실행 유도",
        "준비 중 / 후속 검증",
    ),
    (
        "PI-O01",
        "Encoded / Obfuscated Instruction",
        "Input/Context",
        "변형 지시로 탐지 회피",
        "준비 중 / 후속 검증",
    ),
    (
        "JB-S01",
        "Jailbreak",
        "Input",
        "모델 행동 제약 우회",
        "준비 중 / 실제 LLM 평가 필요",
    ),
    ("TL-U01", "Unauthorized Tool", "Tool", "금지 도구 실행", "준비 중 / 후속 검증"),
    ("TL-A01", "Tool Argument Abuse", "Tool", "도구 인자 변조", "준비 중 / 후속 검증"),
    (
        "TL-X01",
        "Tool-based Data Exfiltration",
        "Context/Tool",
        "도구를 통한 정보 유출",
        "준비 중 / 후속 검증",
    ),
    (
        "OUT-L01",
        "Sensitive Data Leakage",
        "Output",
        "민감정보 전달",
        "카드 3 · 내부 합성 대표 예시",
    ),
)


def render_attack_catalog():
    st.subheader("Attack Playground · 공격 분류 안내")
    st.caption(
        "실행 가능한 시나리오는 위 세 카드입니다. 공격 ID는 분류 안내이며 전체 공격군 검증 완료를 뜻하지 않습니다."
    )
    st.dataframe(
        [
            {
                "Attack ID": key,
                "공격 유형": family,
                "유입 경로": entry,
                "공격 목표": goal,
                "실행 / 검증 상태": status,
            }
            for key, family, entry, goal, status in ATTACKS
        ],
        hide_index=True,
        width="stretch",
    )
    st.caption(
        "정상 카드와 공격 카드는 내부 합성 Mock 데이터입니다. 공개 데이터셋 평가와 구분합니다."
    )


def render_live_comparison():
    from service import SCENARIOS, query_events, run_comparison

    with st.expander("같은 합성 요청의 B/C 실제 Runtime 비교", expanded=False):
        st.caption(
            "B Independent / C Linked · 기본 YAML 0.80 / STRICT 0.50 · 각각 별도 run_id/trace_id · Mock Tool만 실행"
        )
        key = st.selectbox(
            "비교 시나리오",
            list(SCENARIOS),
            format_func=lambda key: SCENARIOS[key]["name"],
            key="comparison_scenario",
        )
        if st.button("B/C 비교 실행", key="run_bc_comparison"):
            try:
                st.session_state["bc_comparison"] = run_comparison(key)
            except Exception as exc:
                logger.exception("B/C comparison failed")
                st.session_state.pop("bc_comparison", None)
                st.error(f"B/C 실행 실패: {exc}")
        snapshots = st.session_state.get("bc_comparison")
        if not snapshots:
            return
        for mode, column in zip(("B", "C"), st.columns(2), strict=True):
            snapshot = snapshots[mode]
            result = snapshot["result"]
            with column:
                st.markdown(f"**{mode} · {snapshot['scenario']['name']}**")
                st.write("요청:", snapshot["scenario"]["prompt"])
                st.write("판정 / 정책:", result.get("decision"))
                st.write("Mock Tool 호출 횟수:", snapshot["tool_calls"])
                st.write("실행 결과:", result.get("execution"))
                st.write("출력 전달:", result["output_allowed"])
                st.json(result["identity"])
                try:
                    st.json(query_events(result["identity"]["run_id"]))
                except Exception as exc:
                    logger.exception("Comparison Evidence query failed")
                    st.error(f"Evidence 조회 실패: {exc}")
        st.caption(
            "이 비교는 현재 코드의 합성 시나리오 실행입니다. Holdout Trial 또는 저장된 실험 비교와 별개이며, B/C 결과가 같을 수도 있습니다."
        )


def render_benchmark_lab():
    from pathlib import Path

    from benchmark_reader import load_holdout, read_json

    st.subheader("Benchmark Lab · 읽기 전용")
    st.caption("저장된 실측 실험 비교 · 실시간 B/C 실행이 아닙니다.")
    st.warning(
        "공격 Mock Tool 실행률은 실제 LLM ASR이 아닙니다. semantic TSR: unknown. ToolPolicy는 권한 설정 효과입니다."
    )
    directory = Path(
        st.text_input(
            "Holdout 인계 디렉터리",
            str(Path(__file__).resolve().parents[1] / "reports" / "holdout"),
            key="holdout_directory",
        )
    ).expanduser()
    report = load_holdout(directory)
    st.info(report["status"])
    for message in report["errors"] + report["warnings"]:
        st.warning(message)
    if report["data"] is None:
        st.write(
            "holdout_results.json, run_record_holdout.json, raw_verification.json 및 figures/를 같은 인계 디렉터리에 배치하세요."
        )
    else:
        st.caption(
            "검증 범위: 제공 파일의 구조·집계·해시 일관성. Runtime 실행 검증: false. Holdout Trial은 run_id/trace_id Evidence와 연결하지 않습니다."
        )
        st.caption(
            "분자는 raw 검증 cell이 제공된 경우만 표시합니다. 누락 값은 unknown이며 0이 아닙니다."
        )
        st.dataframe(report["rows"], hide_index=True, width="stretch")
        policy = st.selectbox(
            "차트 ToolPolicy", ["default", "tool_policy"], key="benchmark_chart_policy"
        )
        chart = [
            row
            for row in report["rows"]
            if row["metric"] == "attack_tool_execution"
            and row["threshold"] is not None
            and row["policy"] == policy
        ]
        st.line_chart(
            chart,
            x="threshold",
            y="rate",
            color="condition",
            x_label="Threshold",
            y_label="Mock Tool execution rate",
        )
        raw = report["raw"]
        if raw:
            with st.expander(
                "원본 산술 검증 보고서 · 정상 read/send 및 출력 전달 / 표본 / Trial"
            ):
                st.json(
                    {
                        "sweeps": raw["sweeps"],
                        "guards": raw.get("guards"),
                        "population_mapping": raw.get("population_mapping"),
                        "c_causes": raw.get("c_causes"),
                        "limitations": raw.get("limitations"),
                    }
                )
        with st.expander("출처 · 정책 · 시각 · SHA256 · C 차단 원인"):
            st.json(
                {
                    "run": report["data"]["run"],
                    "data": report["data"]["data"],
                    "tool_policy": report["data"]["tool_policy"],
                    "sha256": report["hashes"],
                    "notes": report["data"]["notes"],
                    "c_block_cause": report["data"]["c_block_cause"],
                }
            )
        for name in (
            "holdout_attack_tool_execution",
            "holdout_benign_outcomes",
            "holdout_tool_policy",
            "holdout_c_block_causes",
        ):
            image = directory / "figures" / (name + ".png")
            if image.is_file():
                st.image(
                    str(image), caption=name + " · 제공된 그림 / 독립 실행 검증 아님"
                )
            else:
                st.caption(name + " · 그래프 파일 없음")
    with st.expander("Tuning · 별도 실험 / 인계 감사 자료"):
        tuning = Path(
            st.text_input(
                "Tuning 감사 디렉터리",
                str(directory.parent / "tuning"),
                key="tuning_directory",
            )
        )
        for name in ("audit_summary.json", "plot_audit.json"):
            candidate = tuning / name
            if not candidate.is_file():
                st.caption(name + " · 결과 없음")
                continue
            try:
                data = read_json(candidate)
                if name == "audit_summary.json":
                    valid = (
                        data.get("schema_version") == "imported-fatin-audit-v1"
                        and data.get("status") == "arithmetic_audited"
                        and data.get("evidence_validated") is False
                    )
                else:
                    valid = data.get("split") == "tune"
                if not valid:
                    raise ValueError("Tuning 계약 / split 불일치")
                st.json(data)
            except (OSError, ValueError, TypeError) as exc:
                st.warning(f"{name}: {exc}")
        st.caption(
            "Tuning/Holdout 비교 차트는 두 split의 인계가 검증된 후 제작합니다. 누락 자료를 대체하지 않습니다."
        )
    with st.expander("역사적 35샘플 replay · 별도 실험"):
        st.caption(
            "35개 텍스트 replay는 Holdout과 별개입니다. 기존 360 Trial 합성 Fixture는 A/B/C Evaluation 탭에서 확인합니다."
        )
    st.caption(
        "Input/Context/Tool Guard는 실행 전, Output Guard는 실행 후 검사합니다. WARN에서도 Tool은 실행되고 출력만 보류될 수 있습니다."
    )
