"""Read existing runtime evaluation artifacts without recomputing metrics."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
METRICS = {
    "asr": "ASR", "tsr": "TSR", "fpr": "FPR", "block_rate": "Block Rate",
    "average_latency_ms": "Mean (ms)", "p50_latency_ms": "p50 (ms)",
    "p95_latency_ms": "p95 (ms)", "total_runs": "Sample count",
}


def discover_reports(directory: Path) -> tuple[list[tuple[Path, dict]], list[str]]:
    """Only accept completed reports with the current exporter contract."""
    reports, errors = [], []
    if not directory.is_dir():
        return reports, errors
    for path in sorted(directory.rglob("summary.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("status") != "completed":
                raise ValueError("완료된 Runtime report가 아닙니다")
            experiment = data["experiment"]
            if experiment["block_threshold"] not in (0.80, 0.92):
                raise ValueError("지원하지 않는 threshold")
            for mode in ("A", "B", "C"):
                for field in METRICS:
                    data["metrics"][mode][field]
            reports.append((path, data))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{path}: {exc}")
    return reports, errors


def report_rows(data: dict) -> list[dict]:
    return [
        {"Condition": mode, **{label: data["metrics"][mode][key] for key, label in METRICS.items()}}
        for mode in ("A", "B", "C")
    ]


def render_configurations():
    import streamlit as st
    from plugin_view import condition_config

    st.markdown("**Plugin Configuration**")
    for mode, label, column in zip(
        ("A", "B", "C"), ("No Guard", "Independent", "Linked"), st.columns(3), strict=True,
    ):
        config = condition_config(mode)
        with column, st.container(border=True):
            st.markdown(f"**{mode} · {label}**")
            for plugin in config["plugins"]:
                st.caption(f"🧩 {plugin['name']}: {'ON' if plugin['enabled'] else 'OFF'}")
            st.write("Cross-layer Coordination:", "ON" if config["mode"] == "linked" else "OFF")
    st.caption("Architecture only · 현재 condition YAML / PluginManager에서 읽은 구성. B/C는 같은 Guard Plugin을 사용하며 coordination 방식이 다릅니다.")


def render_mechanism_comparison(data):
    import streamlit as st

    st.markdown("**B vs C · Mechanism Comparison**")
    st.caption("Stored Report · 개별 ATTACK 판정 / Tool 실행 여부를 ASR로 역추론하지 않습니다.")
    for mode, column in zip(("B", "C"), st.columns(2), strict=True):
        with column, st.container(border=True):
            st.markdown(f"**{mode} · {'Independent' if mode == 'B' else 'Linked'}**")
            values = data["metrics"][mode]
            st.write("Policy version:", values.get("policy_version", "기록 없음"))
            st.metric("ASR (금지 Tool 실행 비율)", values.get("asr"))
            st.metric("Block Rate (전체 trial)", values.get("block_rate"))
            counts = data.get("sample_counts", {}).get(mode, {})
            if "asr_numerator" in counts and "asr_denominator" in counts:
                st.write("ATTACK Tool 실행 / 표본:", f"{counts['asr_numerator']} / {counts['asr_denominator']}")
            st.caption("개별 WARN/BLOCK 결과는 summary에 없어 표시하지 않습니다.")


def render_evaluation():
    import streamlit as st

    st.subheader("A/B/C Evaluation")
    render_configurations()
    st.warning("0.92는 Cross-layer 위험 누적 메커니즘의 동작 차이를 확인하기 위한 시연용 설정이며, 일반적인 성능 우위를 증명하는 threshold가 아닙니다.")
    st.info("초기 Evaluation Pipeline 검증 결과이며 전체 공격 환경에 대한 최종 보안 성능을 의미하지 않습니다.")
    st.caption("실제 Middleware Runtime · Security Core · Enforcement · SQLite Evidence · Mock Tool · BENIGN-001 1종 · ATTACK-001 1종 · 조건별 반복실행")
    directory = Path(st.text_input("Report directory (하위 폴더 포함)", str(ROOT / "reports"))).expanduser()
    reports, errors = discover_reports(directory)
    for error in errors:
        st.warning(f"Report 읽기 실패: {error}")
    if not reports:
        st.info("Evaluation 결과 파일이 없습니다. 아래 명령으로 생성하거나 검증된 발표용 report를 배치해주세요.")
    for threshold, title in ((0.80, "Baseline 0.80"), (0.92, "Mechanism Demonstration")):
        st.subheader(title)
        matches = [(path, data) for path, data in reports if data["experiment"]["block_threshold"] == threshold]
        if not matches:
            st.caption(f"Threshold {threshold:.2f} report 없음")
            st.code(f"uv run python -m scripts.run_runtime_evaluation --output-dir reports/runtime_{int(threshold * 100):03d} --repeats 30 --seed 42 --block-threshold {threshold:.2f}", language="powershell")
            continue
        selected = st.selectbox("Report 선택", range(len(matches)), key=f"report_{threshold}",
                                format_func=lambda index, matches=matches: str(matches[index][0].parent))
        path, data = matches[selected]
        experiment = data["experiment"]
        st.caption(f"Source: {path} · 생성: {data.get('created_at_utc')} · repeats: {experiment.get('repeats_per_scenario_per_mode')} · total: {experiment.get('total_trials')}")
        st.caption("비율은 0–1, latency는 ms. 반복 수만으로 발표용 검증 여부를 보증하지 않습니다. 임시 smoke report는 공식 발표 결과와 구분하세요.")
        if threshold == 0.92:
            render_mechanism_comparison(data)
        st.dataframe(report_rows(data), hide_index=True, width="stretch")
        for name in ("rates.png", "latency.png"):
            image = path.parent / name
            if image.is_file():
                st.image(str(image))
        csv_path = path.with_suffix(".csv")
        if csv_path.is_file():
            st.download_button("summary.csv 다운로드", csv_path.read_bytes(), file_name="summary.csv", key=f"csv_{threshold}")
        with st.expander("Report metadata / limitations"):
            st.json({"experiment": experiment, "limitations": data.get("limitations"), "environment": data.get("environment")})
