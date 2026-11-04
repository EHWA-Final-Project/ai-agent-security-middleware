# Custom Guard Quickstart

현재 코드에서 검증한 확장 경로는 `GuardPlugin` 구현 → `PluginManager.register_guard()` → Registry의 stage/priority/enabled 선택 → Orchestrator 검사 → Runtime Enforcement다. 운영 중 hot-swap이나 외부 코드 업로드 기능은 제공하지 않는다.

## 실행 및 등록

```powershell
uv run python examples/custom_guard.py
uv run --group demo pytest tests/contract/test_custom_guard_plugin.py tests/unit/test_plugin_registry.py tests/unit/test_plugin_manager.py -q
```

기존 `examples/custom_guard.py`의 `BlockedTermGuard`는 `name`, `stage=INPUT`, `inspect(observation, context)`를 구현한다. `inspect`는 기존 `SecurityResult`를 반환하며 관찰의 run_id/trace_id를 보존한다. 위험도는 0~1, 매칭 결과는 WARN/ALLOW 및 rule_ids/evidence로 전달한다. 임계치에 따른 최종 차단은 Orchestrator가 결정한다. 실제 검사 실패만 예외로 보고한다.

```python
from enums import Stage
from security.policy.conditions import build_plugin_manager, load_condition
from examples.custom_guard import BlockedTermGuard

condition = load_condition("C")
manager = build_plugin_manager(condition)
before = [item.plugin.name for item in manager.registry.all_guards()]
manager.register_guard(BlockedTermGuard({"project-x"}), priority=10)
assert "blocked_term_guard" not in before
assert "blocked_term_guard" in [guard.name for guard in manager.guards_for_stage(Stage.INPUT)]
manager.registry.set_enabled("blocked_term_guard", False)
assert "blocked_term_guard" not in [guard.name for guard in manager.guards_for_stage(Stage.INPUT)]
```

위 조각은 저장소 루트에서 src/shared import 경로를 설정한 실행 환경을 전제로 한다. 바로 실행할 때는 기존 예제 명령을 사용한다. 같은 이름의 재등록은 ValueError다. priority가 작을수록 같은 stage 안에서 먼저 실행되며 다른 stage로 이동하지 않는다. YAML `guards.<name>.enabled/priority`는 이미 등록된 Guard만 설정하며 임의 Python 코드를 불러오지 않는다.

## 조건·실패·Evidence

B/C는 같은 Guard 등록 구조를 사용한다. B는 독립 점수, C는 SecurityContext의 누적 위험·coordination을 적용한다. 기본 YAML의 block 0.80 / strict 0.50을 유지한다. Custom Guard 점수 0.6과 send_email Tool Guard 0.6이 결합하는 계약 테스트에서 C 차단과 B 비차단을 확인한다. 실제 의미·성능 우위의 일반화는 아니다.

Plugin 예외는 Manager 검사 경계에서 ERROR로 격리된다. 기존 정책에 따라 Input 오류는 이후 실행이 가능하고 Tool 단계 오류는 실행 전 fail-closed다. 모든 stage가 동일한 실패 정책이라고 설명하지 않는다. Input/Context/Tool은 도구 실행 전, Output은 실행 후 검사한다.

Dashboard의 Registry 패널은 현재 프로세스의 소스 구성이다. 과거 run에 저장되지 않은 enabled/STRICT 값을 복원한 화면이 아니다. Guard의 실제 run/trace·점수·규칙과 판정은 SQLite SECURITY_RESULT/SECURITY_DECISION/EXECUTION_RESULT에서 확인한다.

기존 SVG 2종은 이 코드 흐름을 설명한다. `guardon_plugin_registration.svg`의 Configure는 Registry 활성화, `guardon_architecture.svg`의 Output은 사후 검사다. 두 파일은 기능 선언이 아닌 구조 설명이며 XML 구조 확인과 별개로 브라우저 시각 검토는 아직 하지 못했다.
