import tempfile
from pathlib import Path

from enums import Stage

from security.plugins.guards.input_guard import InputGuard
from security.plugins.manager import PluginManager

_CONFIG_YAML = """
guards:
  input_guard:
    enabled: false
    priority: 5
"""


def test_manager_loads_config_and_disables_guard():
    manager = PluginManager()
    manager.register_guard(InputGuard())

    with tempfile.TemporaryDirectory() as tmp:
        config_path = Path(tmp) / "guards.yaml"
        config_path.write_text(_CONFIG_YAML, encoding="utf-8")
        manager.load_from_config(str(config_path))

    # Disabled via config -> excluded from stage lookup, no orchestrator code touched.
    assert manager.guards_for_stage(Stage.INPUT) == []


def test_manager_returns_registered_guard_when_enabled():
    manager = PluginManager()
    manager.register_guard(InputGuard())

    guards = manager.guards_for_stage(Stage.INPUT)
    assert len(guards) == 1
    assert guards[0].name == "input_guard"
