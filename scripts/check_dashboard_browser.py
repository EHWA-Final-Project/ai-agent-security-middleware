"""Opt-in real Chrome checks; use uv run --with playwright, no runtime dependency."""

import argparse
import hashlib
import json
from pathlib import Path

VIEWS = [
    ("overview", "실험 개요", "실험 개요"),
    ("agent", "Agent 실행", "Agent–MCP 실행 관측"),
    ("comparison", "A/B/C/D 비교", "A/B/C/D 조건 비교"),
    ("benchmark", "외부 벤치마크", "외부 벤치마크 평가"),
    ("evidence", "Evidence 조사", "Evidence / Trace 조사"),
]


def contrast(foreground, background):
    def luminance(color):
        rgb = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in rgb]
        return sum(c * weight for c, weight in zip(linear, (.2126, .7152, .0722), strict=True))
    light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
    return (light + .05) / (dark + .05)


def ready(page):
    from playwright.sync_api import expect
    footer = page.get_by_text("기존 Workbench 열기 · Fixture/Mock 자료", exact=True)
    footer.first.wait_for()
    page.locator('[data-testid="stStatusWidget"]').wait_for(state="hidden")
    expect(footer).to_have_count(1)
    expect(page.locator("h2")).to_have_count(1)
    expect(page.locator('[data-stale="true"]')).to_have_count(0)
    if "view=benchmark" in page.url:
        page.locator('[data-testid="stVegaLiteChart"] svg, [data-testid="stVegaLiteChart"] canvas').first.wait_for()
    page.evaluate("async () => { await document.fonts.ready; }")
    page.evaluate("() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))")


def main():
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8502")
    parser.add_argument("--output-dir", type=Path, default=Path(".cache/browser-qa"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    pairs = [("body", "#172B42", "#F5F7FA"), ("secondary", "#516176", "#F5F7FA"),
             ("allow", "#075E58", "#E4F1ED"), ("block", "#A32D3D", "#FAEBEE"),
             ("warn", "#805100", "#FCF2DB")]
    ratios = {name: round(contrast(fg, bg), 2) for name, fg, bg in pairs}
    assert all(ratio >= 4.5 for ratio in ratios.values())
    result = {"browser": None, "screens": [], "interaction_checks": {}, "text_contrast_ratios": ratios}
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        result["browser"] = {"engine": "Chrome headless", "version": browser.version}
        for width, height in [(1920, 1080), (1366, 768)]:
            page = browser.new_page(viewport={"width": width, "height": height}, device_scale_factor=1)
            errors = []
            page.on("pageerror", lambda error, collected=errors: collected.append(str(error)))
            page.goto(f"{args.url}/?view=overview")
            ready(page)
            for slug, label, title in VIEWS:
                page.get_by_role("radiogroup", name="분석 화면").get_by_text(label, exact=True).click()
                page.get_by_role("heading", name=title, exact=True).wait_for()
                ready(page)
                assert f"view={slug}" in page.url, page.url
                assert page.locator('[data-testid="stException"]').count() == 0
                stats = page.evaluate("""() => ({
                    page_overflow: document.documentElement.scrollWidth > innerWidth,
                    main_overflow: document.querySelector('.stMain').scrollWidth > document.querySelector('.stMain').clientWidth,
                    content_width: document.querySelector('.stMainBlockContainer').getBoundingClientRect().width,
                    caption_color: getComputedStyle(document.querySelector('[data-testid="stCaptionContainer"] p') || document.querySelector('.console-kicker')).color,
                    caption_opacity: getComputedStyle(document.querySelector('[data-testid="stCaptionContainer"]')).opacity,
                    flow_overflow: [...document.querySelectorAll('.console-flow, .console-flow span, .console-flow strong')].some(e => e.scrollWidth > e.clientWidth + 2)
                })""")
                assert not stats["page_overflow"] and not stats["main_overflow"] and not stats["flow_overflow"], stats
                assert stats["caption_color"] == "rgb(81, 97, 118)" and stats["caption_opacity"] == "1", stats
                assert not errors, errors
                filename = f"{slug}-{width}x{height}.png"
                page.screenshot(path=str(args.output_dir / filename), animations="disabled")
                result["screens"].append({"view": slug, "viewport": [width, height], "screenshot": filename, "layout": stats, "page_errors": list(errors)})
            page.close()
            print(f"{width}x{height}: five views, navigation and overflow checks passed", flush=True)

        page = browser.new_page(viewport={"width": 1366, "height": 768})
        page.goto(f"{args.url}/?view=overview")
        ready(page)
        page.get_by_role("radio", name="실험 개요", exact=True).focus()
        page.keyboard.press("ArrowRight")
        page.get_by_role("heading", name="Agent–MCP 실행 관측", exact=True).wait_for()
        ready(page)
        result["interaction_checks"]["keyboard_navigation"] = "passed"
        page.get_by_role("combobox").click()
        page.get_by_role("option").filter(has_text="C · 정상·실행 전 차단 · external-unauthorized-email-001").click()
        page.get_by_text("실행 전 차단", exact=True).wait_for()
        ready(page)
        page.screenshot(path=str(args.output_dir / "pre-block-1366x768.png"), animations="disabled")
        page.get_by_role("combobox").click()
        page.get_by_role("option").filter(has_text="C · 실행 후 출력 통제 · external-output-block-001").click()
        page.get_by_text("실행 후 출력 통제", exact=True).wait_for()
        ready(page)
        page.screenshot(path=str(args.output_dir / "post-block-1366x768.png"), animations="disabled")
        result["interaction_checks"]["historical_pre_post_block"] = "passed"
        page.get_by_text("정책 · Run/Trace · Evidence ID · SDK 시각 · 원본 필드", exact=True).click()
        page.get_by_text("evidence_refs", exact=False).first.wait_for()
        result["interaction_checks"]["evidence_disclosure"] = "passed"
        page.close()

        page = browser.new_page(viewport={"width": 1366, "height": 768})
        page.goto(f"{args.url}/?view=benchmark")
        ready(page)
        for tab, caption in [("실행 상태", "조건별 완료·Timeout·오류"), ("실행 경계", "Tool 실행과 출력 전달 경계"),
                             ("비인가 Tool", "비인가 Tool의 선택과 실행"), ("응답 분석", "생성 응답의 사후 분석 범위"),
                             ("Latency", "Backend Latency (s) · LLM 포함 · 완료 표본만")]:
            tab_control = page.get_by_role("tab", name=tab, exact=True)
            tab_control.click()
            page.get_by_role("img", name=caption, exact=True).wait_for()
            assert tab_control.get_attribute("aria-selected") == "true"
        page.screenshot(path=str(args.output_dir / "latency-1366x768.png"), animations="disabled")
        result["interaction_checks"]["five_original_graph_tabs"] = "passed"
        with page.expect_download() as download:
            page.get_by_role("button", name="Trial 관측 CSV 다운로드", exact=True).click()
        downloaded = download.value
        expected = Path(__file__).resolve().parents[1] / "reports/external_mcp_actual/dashboard/trial_observations.csv"
        assert downloaded.suggested_filename == "trial_observations.csv"
        assert hashlib.sha256(Path(downloaded.path()).read_bytes()).digest() == hashlib.sha256(expected.read_bytes()).digest()
        result["interaction_checks"]["csv_export_matches_original"] = "passed"
        page.close()

        page = browser.new_page(viewport={"width": 390, "height": 844}, reduced_motion="reduce")
        page.goto(f"{args.url}/?view=overview")
        ready(page)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.screenshot(path=str(args.output_dir / "overview-390x844.png"))
        result["interaction_checks"]["narrow_viewport_reduced_motion"] = "passed"
        browser.close()
    (args.output_dir / "browser-qa.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Browser checks passed", flush=True)


if __name__ == "__main__":
    main()
