# 실제 브라우저 Before / After

Before는 최신 dev `ce81fbb`의 Streamlit(8503), After는 별도 React 앱(5173)이다. Chrome headless에서 실제 화면을 캡처했다. 시안이나 합성 이미지가 아니다.

| 화면 | Before 1366×768 | React 1366×768 | React 1920×1080 |
|---|---|---|---|
| Overview | [기존](before/overview-1366x768.png) | [새 화면](after/overview-1366x768.png) | [새 화면](after/overview-1920x1080.png) |
| Agent Execution | [기존](before/agent-1366x768.png) | [새 화면](after/agent-1366x768.png) | [새 화면](after/agent-1920x1080.png) |
| A/B/C/D Comparison | [기존](before/comparison-1366x768.png) | [새 화면](after/comparison-1366x768.png) | [새 화면](after/comparison-1920x1080.png) |
| External Benchmark | [기존](before/benchmark-1366x768.png) | [새 화면](after/benchmark-1366x768.png) | [새 화면](after/benchmark-1920x1080.png) |
| Evidence Explorer | [기존](before/evidence-1366x768.png) | [새 화면](after/evidence-1366x768.png) | [새 화면](after/evidence-1920x1080.png) |

추가 캡처: [실행 전 차단](after/pre-block-1366x768.png), [실행 후 출력 통제](after/post-block-1366x768.png), [우측 Evidence](after/evidence-panel-1366x768.png), [원본 Latency](after/latency-original.png), [모바일](after/overview-390x844.png).

브라우저 검사: [Before 기록](before/browser-qa.json), [React 기록](after/browser-qa.json). 재현 명령과 스킬별 적용 근거는 [인계 문서](../../REACT_DASHBOARD_HANDOFF.md)를 참고한다.
