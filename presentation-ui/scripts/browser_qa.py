"""Exercise the production React UI in actual Chrome; no model or Tool calls."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def repository_bytes(relative):
    return subprocess.run(["git", "show", f"HEAD:{relative}"], cwd=ROOT, check=True, capture_output=True).stdout


VIEWS = [("overview", "Overview", "실험 현황"), ("agent", "Agent Execution", "Agent 실행 Trace"),
         ("comparison", "A/B/C/D Comparison", "A/B/C/D 조건 비교"),
         ("benchmark", "External Benchmark", "외부 벤치마크 평가"), ("evidence", "Evidence Explorer", "Evidence 조사")]


def ready(page):
    page.locator(".app-footer").wait_for()
    page.locator(".loading").wait_for(state="hidden")
    page.evaluate("async () => { await document.fonts.ready; await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r))); }")


def main():
    from playwright.sync_api import expect, sync_playwright
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5173")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "docs/assets/react-dashboard/after")
    args = parser.parse_args()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((ROOT / "presentation-ui/public/data/guardon.json").read_text(encoding="utf-8"))
    report = {"mode": "recorded", "screens": [], "checks": {}, "browser": None}
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        report["browser"] = {"name": "Chrome headless", "version": browser.version}
        for width, height in [(1920, 1080), (1366, 768)]:
            page = browser.new_page(viewport={"width": width, "height": height}, reduced_motion="reduce")
            errors = []
            page.on("pageerror", lambda e, collected=errors: collected.append(str(e)))
            page.goto(args.url)
            ready(page)
            for view, label, title in VIEWS:
                page.get_by_role("navigation", name="주요 분석 화면").get_by_role("link").filter(has_text=label).click()
                page.get_by_role("heading", name=title, exact=True).wait_for()
                ready(page)
                expect(page.get_by_role("heading", level=1)).to_have_count(1)
                assert not errors, errors
                assert f"view={view}" in page.url
                assert page.get_by_text("Deploy", exact=True).count() == 0
                geometry = page.evaluate("""() => ({pageOverflow:document.documentElement.scrollWidth>innerWidth,
                  mainOverflow:document.querySelector('main').scrollWidth>document.querySelector('main').clientWidth,
                  sidebarWidth:document.querySelector('.sidebar').getBoundingClientRect().width,
                  headingSize:getComputedStyle(document.querySelector('h1')).fontSize})""")
                assert not geometry["pageOverflow"] and not geometry["mainOverflow"], geometry
                filename = f"{view}-{width}x{height}.png"
                page.screenshot(path=str(out / filename), animations="disabled")
                report["screens"].append({"view": view, "viewport": [width, height], "screenshot": filename, "geometry": geometry, "pageErrors": list(errors)})
            page.close()
            print(f"{width}x{height}: 5 production views and navigation passed", flush=True)

        context = browser.new_context(viewport={"width": 1366, "height": 768}, reduced_motion="reduce", permissions=["clipboard-read", "clipboard-write"])
        page = context.new_page()
        page.goto(f"{args.url}/?view=agent")
        ready(page)
        for scenario, expected, sdk in [("external-unauthorized-email-001", "실행 전 차단", "0"), ("external-output-block-001", "실행 후 출력 통제", "1")]:
            page.locator(".runtime-list").get_by_role("button", name=re.compile(rf"^C.*{scenario}", re.DOTALL)).click()
            expect(page.locator(".trace-summary h3")).to_have_text(expected)
            expect(page.locator(".timeline .stage-value").nth(2)).to_have_text(sdk)
            page.screenshot(path=str(out / f"{'pre' if sdk == '0' else 'post'}-block-1366x768.png"), animations="disabled")
        report["checks"]["historical_pre_post_boundary"] = "passed"
        page.locator(".runtime-list").get_by_role("button", name=re.compile(r"^C.*external-multistep-normal-001", re.DOTALL)).click()
        page.locator(".candidate-tabs").get_by_role("button").filter(has_text="candidate-2").click()
        expect(page.locator(".candidate-tabs button[aria-pressed=true]")).to_contain_text("candidate-2")
        page.get_by_role("button", name="Evidence 상세", exact=True).click()
        dialog = page.get_by_role("dialog")
        expect(dialog).to_be_visible()
        page.get_by_role("button", name="Run ID 복사", exact=True).click()
        expect(dialog.get_by_role("status")).to_contain_text("복사했습니다")
        page.screenshot(path=str(out / "evidence-panel-1366x768.png"), animations="disabled")
        page.keyboard.press("Escape")
        expect(page.get_by_role("dialog")).not_to_be_visible()
        expect(page.get_by_role("button", name="Evidence 상세", exact=True)).to_be_focused()
        report["checks"]["candidate_panel_copy_escape_focus"] = "passed"

        run = data["trials"][0]["run_id"]
        search = page.get_by_role("textbox", name="기록 검색", exact=True)
        search.fill(run)
        search.press("Enter")
        page.get_by_role("heading", name="Evidence 조사", exact=True).wait_for()
        expect(page.locator(".run-list tbody tr")).to_have_count(1)
        page.reload()
        ready(page)
        expect(page.get_by_role("textbox", name="기록 검색", exact=True)).to_have_value(run)
        expect(page.locator(".run-list tbody tr")).to_have_count(1)
        page.get_by_role("textbox", name="기록 검색", exact=True).fill("not-a-real-run")
        expect(page.locator(".run-list .empty-state")).to_be_visible()
        page.get_by_role("button", name="검색 지우기").click()
        page.get_by_label("조건", exact=True).select_option("D")
        expect(page.locator(".run-list .pagination")).to_contain_text("12개")
        page.get_by_label("실행 상태", exact=True).select_option("timeout")
        expect(page.locator(".run-list tbody tr")).to_have_count(1)
        report["checks"]["search_filter_empty_and_reload"] = "passed"

        page.goto(f"{args.url}/?view=benchmark")
        ready(page)
        page.get_by_label("조건", exact=True).select_option("D")
        page.get_by_label("관측 범위", exact=True).select_option("all_saved_attempts_diagnostic")
        page.get_by_role("button", name="observed_pre_execution_block 분모와 제외 사유", exact=True).click()
        dialog = page.get_by_role("dialog")
        expect(dialog).to_be_visible()
        field = dialog.locator(".facts > div").filter(has=page.get_by_text("조건", exact=True)).locator("dd")
        expect(field).to_have_text("D")
        expect(dialog.locator(".facts")).to_contain_text("all_saved_attempts_diagnostic")
        page.keyboard.press("Escape")
        report["checks"]["metric_scope_and_condition_preserved"] = "passed"
        for graph in data["graphs"]:
            page.get_by_role("group", name="원본 그래프 선택").get_by_role("button", name=graph["title"], exact=True).click()
            img = page.get_by_role("img", name=graph["title"], exact=True)
            img.wait_for()
            expect(img).to_have_attribute("src", "/" + graph["src"])
            page.wait_for_function("() => { const i=document.querySelector('.original-graph img'); return i.complete && i.naturalWidth>0; }")
            response = page.request.get(f"{args.url}/{graph['src']}")
            assert response.body() == (ROOT / "presentation-ui/public" / graph["src"]).read_bytes()
        page.locator(".original-graph").screenshot(path=str(out / "latency-original.png"), animations="disabled")
        with page.expect_download() as download:
            page.get_by_role("link", name="Trial CSV", exact=True).click()
        assert Path(download.value.path()).read_bytes() == repository_bytes("reports/external_mcp_actual/dashboard/trial_observations.csv")
        report["checks"]["five_original_graphs_and_csv_bytes"] = "passed"

        page.goto(f"{args.url}/?view=comparison")
        ready(page)
        page.get_by_label("표본", exact=True).select_option("msb-mcp-d01-pair-001:attack")
        expect(page.locator(".comparison-matrix thead .condition")).to_have_count(4)
        page.get_by_role("button", name="Trace 조사", exact=True).nth(2).click()
        expect(page.get_by_role("dialog")).to_be_visible()
        page.keyboard.press("Escape")
        report["checks"]["matched_sample_matrix_and_evidence"] = "passed"
        context.close()

        page = browser.new_page(viewport={"width": 390, "height": 844}, reduced_motion="reduce")
        page.goto(args.url)
        ready(page)
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        page.screenshot(path=str(out / "overview-390x844.png"), animations="disabled")
        page.get_by_role("button", name="탐색 메뉴 열기").click()
        page.get_by_role("navigation", name="주요 분석 화면").get_by_role("link").filter(has_text="Agent Execution").click()
        page.get_by_role("heading", name="Agent 실행 Trace", exact=True).wait_for()
        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
        report["checks"]["mobile_navigation_reduced_motion"] = "passed"
        page.close()
        page = browser.new_page()
        page.route("**/data/guardon.json", lambda route: route.abort())
        page.goto(args.url)
        page.get_by_role("heading", name="실험 데이터를 읽을 수 없습니다", exact=True).wait_for()
        expect(page.get_by_role("button", name="다시 불러오기")).to_be_visible()
        report["checks"]["real_load_error_state"] = "passed"
        page.close()
        browser.close()
    for relative, digest in data["sourceHashes"].items():
        assert hashlib.sha256(repository_bytes(relative)).hexdigest() == digest
    report["checks"]["source_files_unchanged"] = "passed"
    (out / "browser-qa.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("All React browser checks passed", flush=True)


if __name__ == "__main__":
    main()
