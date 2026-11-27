"""Presentation primitives for the read-only research console."""

from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st
from actual_results import display

LABELS = {
    "condition": "조건", "status": "실행 상태", "classification": "표본 유형",
    "dataset": "데이터셋", "candidate_id": "Candidate", "tool_name": "선택 Tool",
    "aggregate_decision": "최종 판정", "security_decision": "최종 판정",
    "sdk_call_count": "SDK 호출", "server_tool_execution_count": "서버 실행",
    "output_allowed": "출력 허용", "output_delivered": "모델 전달",
    "output_guard_block": "Output Guard BLOCK", "toolpolicy_denial": "ToolPolicy 차단",
    "rule_ids": "triggered_rules", "guard_name": "Guard", "decision": "개별 판정",
    "stage": "검사 단계", "evidence_id": "Evidence ID", "model_turn": "모델 턴",
    "entered_runtime": "Runtime 진입", "tool_sdk_calls": "SDK 호출",
    "candidate_count": "후보 수", "unauthorized_selection": "비인가 선택",
    "unauthorized_execution": "비인가 실행", "sample_id": "표본 ID",
    "run_id": "Run ID", "trace_id": "Trace ID", "model": "모델",
    "turn": "턴", "tool_call_count": "선택 Tool 수", "finish_reason": "종료 이유",
    "method": "SDK 메서드", "timestamp": "관측 시각 (UTC)", "invoked": "SDK 진입",
    "execution_state": "실행 상태", "tool_executed": "실행됨", "executed": "실행됨",
    "scope": "관측 범위", "metric": "지표", "numerator": "분자", "denominator": "분모",
    "denominator_unit": "단위", "sample_coverage": "표본 수", "rate": "관측 비율",
    "excluded_or_unknown_count": "제외·미확인", "backend_latency_ms": "Backend (ms)",
}


def text(value):
    return escape(str(display(value)))


def install_style():
    st.html(f"<style>{Path(__file__).with_suffix('.css').read_text(encoding='utf-8')}</style>")
    st.html('<a class="console-skip" href="#analysis-content">분석 본문으로 이동</a>')


def heading(title, description):
    st.html('<div id="analysis-content" class="console-anchor"></div>')
    st.header(title)
    st.caption(description)


def metrics(items):
    st.html('<dl class="console-metrics">' + ''.join(
        f'<div><dt>{text(label)}</dt><dd>{text(value)}</dd><small>{text(note)}</small></div>'
        for label, value, note in items) + '</dl>')


def flow(items):
    st.html('<ol class="console-flow" aria-label="실행 흐름">' + ''.join(
        f'<li><strong>{text(label)}</strong><span>{text(detail)}</span></li>'
        for label, detail in items) + '</ol>')


def facts(items):
    st.html('<dl class="console-facts">' + ''.join(
        f'<div><dt>{text(label)}</dt><dd>{text(value)}</dd></div>' for label, value in items) + '</dl>')


def table(rows, columns=None, *, alt="관측 데이터 표"):
    if not rows:
        st.info("기록 없음 · 알 수 없음. 다른 Trial을 선택하거나 원본 기록을 확인하세요.")
        return
    if columns:
        rows = [{key: row.get(key) for key in columns} for row in rows]
    frame = pd.DataFrame([{k: str(display(v)) for k, v in row.items()} for row in rows])
    st.dataframe(frame, width="stretch", hide_index=True, row_height=42,
                 height=min(440, 44 + 42 * len(rows)), alt=alt,
                 column_config={key: st.column_config.TextColumn(LABELS.get(key, key)) for key in frame.columns})


def raw_details(label, data):
    with st.expander(label, expanded=False):
        st.json(data)


def readable_table(rows, columns=None, *, alt="핵심 관측 결과"):
    """Small semantic tables for presentation; full raw fields remain inspectable."""
    if not rows:
        table(rows)
        return
    columns = columns or list(rows[0])
    headers = ''.join(f'<th scope="col">{text(LABELS.get(k, k))}</th>' for k in columns)
    body = []
    statuses = {"ALLOW": ("allow", "ALLOW"), "BLOCK": ("block", "BLOCK"),
                "WARN": ("warn", "WARN"), "completed": ("allow", "완료"),
                "timeout": ("warn", "Timeout"), "error": ("block", "오류")}
    for row in rows:
        cells = []
        for key in columns:
            value = row.get(key)
            if isinstance(value, str) and value in statuses:
                style, label = statuses[value]
                rendered = f'<span class="console-state {style}">{text(label)}</span>'
            else:
                rendered = text(value)
            cells.append(f'<td class="numeric">{rendered}</td>')
        body.append('<tr>' + ''.join(cells) + '</tr>')
    st.html(f'<div class="console-table-scroll" role="region" tabindex="0" aria-label="{text(alt)}">'
            f'<table class="console-table"><thead><tr>{headers}</tr></thead><tbody>{"".join(body)}</tbody></table></div>')


def execution_summary(row, *, runtime=False):
    executed = row.get("tool_executed" if runtime else "executed")
    decision = row.get("security_decision" if runtime else "aggregate_decision")
    server = row.get("server_call_counts" if runtime else "server_tool_execution_count")
    server_display = " · ".join(f"{key} {display(value)}" for key, value in server.items()) if isinstance(server, dict) else display(server)
    if executed is False and (row.get("execution_state") == "BLOCKED" or row.get("pre_execution_block") is True):
        title, style = "실행 전 차단", "block"
    elif executed is True and row.get("output_allowed") is False:
        title, style = "실행 후 출력 통제", "withheld"
    elif executed is True:
        title, style = "Tool 실행 관측", "allow"
    else:
        title, style = "실행 경계 미확인", "unknown"
    st.html(f'<section class="console-outcome {style}" aria-label="실행 경계">'
            f'<strong>{text(title)}</strong><p>실행 여부 · {text(executed)}　 /　최종 집계 판정 · {text(decision)}</p></section>')
    flow([("모델 선택", row.get("tool_name")), ("SDK 호출", row.get("sdk_call_count")),
          ("서버 실행", server_display),
          ("후속 모델 전달", row.get("output_delivered"))])
    if executed is True and decision == "BLOCK":
        st.info("EXECUTED + 최종 BLOCK · 이미 수행된 Tool 실행과 출력 전달 통제를 구분합니다.")
