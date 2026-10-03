"""Plugin Manager.

Bootstraps the PluginRegistry from config and exposes stage-based guard
lookup for the Orchestrator to call. The Orchestrator never imports a
concrete Guard class directly — it only talks to the Manager/Registry.
"""

from __future__ import annotations

from enums import Stage

from security.plugins.config_loader import load_guard_config
from security.plugins.interface import GuardPlugin
from security.plugins.registry import PluginRegistry


class PluginManager:
    def __init__(self, registry: PluginRegistry | None = None) -> None:
        self.registry = registry or PluginRegistry()

    def load_from_config(self, config_path: str) -> None:
        """Apply enabled/priority settings from a config file to already
        registered guards. Registration itself (which classes exist) still
        happens via `register_guard` — config only controls activation.
        """
        settings = load_guard_config(config_path)
        for name, opts in settings.items():
            if self.registry.get(name) is None:
                continue
            if "enabled" in opts:
                self.registry.set_enabled(name, bool(opts["enabled"]))
            if "priority" in opts:
                self.registry.set_priority(name, int(opts["priority"]))

    def register_guard(self, plugin: GuardPlugin, **kwargs) -> None:
        self.registry.register(plugin, **kwargs)

    def guards_for_stage(self, stage: Stage) -> list[GuardPlugin]:
        return self.registry.guards_for_stage(stage)
