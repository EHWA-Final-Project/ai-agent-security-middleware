"""Plugin Registry.

Holds the set of active Guard plugins. Adding/removing/reordering a Guard
is purely a registry operation — Orchestrator code never changes.
"""

from __future__ import annotations

from dataclasses import dataclass

from enums import Stage

from security.plugins.interface import GuardPlugin


@dataclass
class RegisteredGuard:
    plugin: GuardPlugin
    enabled: bool = True
    priority: int = 100  # lower runs first within the same stage


class PluginRegistry:
    """In-memory registry of Guard plugins, keyed by unique name."""

    def __init__(self) -> None:
        self._guards: dict[str, RegisteredGuard] = {}

    def register(self, plugin: GuardPlugin, *, enabled: bool = True, priority: int = 100) -> None:
        if plugin.name in self._guards:
            raise ValueError(f"Guard '{plugin.name}' is already registered")
        self._guards[plugin.name] = RegisteredGuard(plugin=plugin, enabled=enabled, priority=priority)

    def unregister(self, name: str) -> None:
        self._guards.pop(name, None)

    def set_enabled(self, name: str, enabled: bool) -> None:
        if name not in self._guards:
            raise KeyError(f"Guard '{name}' is not registered")
        self._guards[name].enabled = enabled

    def set_priority(self, name: str, priority: int) -> None:
        if name not in self._guards:
            raise KeyError(f"Guard '{name}' is not registered")
        self._guards[name].priority = priority

    def get(self, name: str) -> RegisteredGuard | None:
        return self._guards.get(name)

    def guards_for_stage(self, stage: Stage) -> list[GuardPlugin]:
        """Return enabled guards for a stage, ordered by priority (ascending)."""
        matches = [
            rg for rg in self._guards.values()
            if rg.enabled and rg.plugin.stage == stage
        ]
        matches.sort(key=lambda rg: rg.priority)
        return [rg.plugin for rg in matches]

    def all_guards(self) -> list[RegisteredGuard]:
        return list(self._guards.values())
