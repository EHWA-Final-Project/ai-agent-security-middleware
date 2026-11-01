"""UI-only contest guidance; no new execution or benchmark contracts."""

import streamlit as st

ATTACKS = (
    ("PI-D01", "Direct Prompt Injection", "Input", "지침 우회", "카드 2 · 내부 합성 대표 예시"),
    ("PI-I01", "Indirect Prompt Injection", "Context", "외부 문맥으로 실행 유도", "준비 중 / 후속 검증"),
    ("PI-T01", "Tool Response Injection", "Tool", "도구 응답으로 후속 실행 유도", "준비 중 / 후속 검증"),
    ("PI-O01", "Encoded / Obfuscated Instruction", "Input/Context", "변형 지시로 탐지 회피", "준비 중 / 후속 검증"),
    ("JB-S01", "Jailbreak", "Input", "모델 행동 제약 우회", "준비 중 / 실제 LLM 평가 필요"),
    ("TL-U01", "Unauthorized Tool", "Tool", "금지 도구 실행", "준비 중 / 후속 검증"),
    ("TL-A01", "Tool Argument Abuse", "Tool", "도구 인자 변조", "준비 중 / 후속 검증"),
    ("TL-X01", "Tool-based Data Exfiltration", "Context/Tool", "도구를 통한 정보 유출", "준비 중 / 후속 검증"),
    ("OUT-L01", "Sensitive Data Leakage", "Output", "민감정보 전달", "카드 3 · 내부 합성 대표 예시"),
)


def render_attack_catalog():
    st.subheader("Attack Playground · 공격 분류 안내")
    st.caption("실행 가능한 시나리오는 위 세 카드입니다. 공격 ID는 분류 안내이며 전체 공격군 검증 완료를 뜻하지 않습니다.")
    st.dataframe([
        {"Attack ID": key, "공격 유형": family, "유입 경로": entry,
         "공격 목표": goal, "실행 / 검증 상태": status}
        for key, family, entry, goal, status in ATTACKS
    ], hide_index=True, width="stretch")
    st.caption("정상 카드와 공격 카드는 내부 합성 Mock 데이터입니다. 공개 데이터셋 평가와 구분합니다.")


def render_benchmark_lab():
    st.subheader("Benchmark Lab · 읽기 전용")
    st.info("평가 결과 준비 중")
    st.write("Wana의 공개 Benchmark 결과 파일과 출력 계약이 확정되면 연결합니다.")
    st.caption("현재 A/B/C Evaluation 탭은 기존 합성 Fixture의 저장된 실측 Report만 표시합니다.")
    st.dataframe([
        {"표시 예정 항목": group, "상태": "결과 / 계약 인계 대기"}
        for group in (
            "Dataset 이름 · 버전 · 출처 / Attack family",
            "A/B/C condition · Threshold · 고유 공격/정상 표본 수 · 총 Trial 수",
            "ASR · TSR · FPR · Block Rate",
            "Mean / p50 / p95 Latency (ms)",
            "실행 전 Tool 차단 / 실행 후 Output 차단",
            "실제 Jailbreak 평가 · Precision / Recall / F1 (산출된 경우만)",
        )
    ], hide_index=True, width="stretch")
    st.caption("미제공 지표는 수치로 채우지 않습니다. 새 공식 Schema나 평가 산식을 정의하지 않습니다.")
