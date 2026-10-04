"""Local composition helper; Platform can replace this factory at integration."""

from security.orchestrator.orchestrator import SecurityOrchestrator
from security.plugins.guards.context_guard import ContextGuard
from security.plugins.guards.input_guard import InputGuard
from security.plugins.guards.output_guard import OutputGuard
from security.plugins.guards.tool_guard import ToolGuard
from security.plugins.manager import PluginManager


def make_security_factory(policy, evidence_sink, *, guard_timeout_sec=2.0):
    def factory(enforcement):
        manager = PluginManager()
        for guard in (InputGuard(), ContextGuard(), ToolGuard(), OutputGuard()):
            manager.register_guard(guard)
        return SecurityOrchestrator(
            manager,
            policy,
            enforcement,
            evidence_sink,
            guard_timeout_sec=guard_timeout_sec,
        )

    return factory
