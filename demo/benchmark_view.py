"""Presentation of supplied benchmark metadata; no measurements or estimates."""

import streamlit as st


def render_details(report):
    data, raw = report["data"], report["raw"]
    with st.expander("Experiment Overview · Holdout"):
        st.json(
            {
                "split": data["split"],
                "dataset": data["data"],
                "run": data["run"],
                "headline_threshold": data["headline_block_threshold"],
                "guard_population": raw.get("guards", {}).get("totals")
                if raw
                else None,
            }
        )
        if raw:
            st.dataframe(
                [
                    {
                        "policy": name,
                        "trial_n": sweep.get("rows"),
                        "unique_sample_n": sweep.get("unique_sample_ids"),
                        "scenario_trials_per_condition": sweep.get(
                            "scenario_trials_per_condition"
                        ),
                        "condition_cells": sweep.get("conditions"),
                    }
                    for name, sweep in raw["sweeps"].items()
                ],
                hide_index=True,
                width="stretch",
            )
        else:
            st.caption(
                "고유 sample / 전체 Trial / Guard-only 정상 오탐: unknown · 제공 검증 자료 없음"
            )
    threshold = st.selectbox(
        "결과 상세 Threshold",
        sorted({r["threshold"] for r in report["rows"] if r["threshold"] is not None}),
        key="benchmark_detail_threshold",
    )
    with st.expander("B/C Threshold Comparison · 실행 전/후 차단"):
        rows = [
            r
            for r in report["rows"]
            if r["threshold"] == threshold
            and r["metric"]
            in ("attack_tool_execution", "pre_tool_block", "output_block")
        ]
        st.dataframe(rows, hide_index=True, width="stretch")
        st.caption(
            "Output BLOCK은 이미 실행된 Tool을 미실행으로 바꾸지 않습니다. 분자는 검증 보고서에 있는 경우만 표시합니다."
        )
    with st.expander("Blocking Mechanism · 실제 원인 count"):
        if data["c_block_cause"]:
            st.dataframe(data["c_block_cause"], hide_index=True, width="stretch")
        else:
            st.caption("원인 count: unknown")
        st.caption(
            "single_guard_ge_thr는 차단 원인에 더할 수 없는 중복 부분집합입니다. cumulative_risk / strict_warn_escalation을 구분합니다."
        )
    with st.expander("Benign Behavior · 정상 read/send 및 출력 전달"):
        st.dataframe(
            [
                r
                for r in report["rows"]
                if r["threshold"] == threshold
                and r["metric"].startswith(("completion_", "fpr_"))
            ],
            hide_index=True,
            width="stretch",
        )
        if raw:
            st.json({"guard_only": raw.get("guards", {}).get("totals")})
        st.caption(
            "completion은 Tool 실행 AND 반환 결과 전달입니다. semantic TSR 및 실제 이메일 전송 성공률은 unknown입니다."
        )
    with st.expander("Policy Comparison · 권한 설정 효과"):
        st.json(data["tool_policy"])
        st.caption(
            "default와 configured ToolPolicy를 별도 표시합니다. Allowlist에 의한 차단은 Guard 탐지 정확도가 아닙니다."
        )
    with st.expander("Validation · Schema / SHA256 / Known Limitations"):
        st.json(
            {
                "reader_status": report["status"],
                "runtime_execution_verified": False,
                "schema": raw.get("schema_version") if raw else None,
                "sha256": report["hashes"],
                "aggregate": report["aggregate"],
                "limitations": raw.get("limitations") if raw else data["notes"],
            }
        )
    st.caption(
        "Performance: Core-only Latency는 별도 Tuning 감사 패널의 제공값만 표시합니다. 자료 미제공 시 mean/p50/p95는 unknown입니다."
    )
