"""Condition A/B/C config files and loader."""

import pytest
from enums import Stage

from security.policy.conditions import (
    CONDITION_FILES,
    build_plugin_manager,
    condition_from_policy_version,
    condition_path,
    load_condition,
)
from security.policy.config import CoordinationMode

GUARD_NAMES = {"input_guard", "context_guard", "tool_guard", "output_guard"}


def test_every_condition_file_exists():
    for name in CONDITION_FILES:
        assert condition_path(name).is_file()


def test_condition_name_is_case_insensitive():
    assert load_condition("c").name == "C"
    assert load_condition("c").policy == load_condition("C").policy


def test_unknown_condition_is_rejected():
    with pytest.raises(ValueError, match="unknown condition"):
        load_condition("Z")


def test_a_has_every_guard_disabled():
    manager = build_plugin_manager(load_condition("A"))
    registered = {rg.plugin.name: rg.enabled for rg in manager.registry.all_guards()}

    assert set(registered) == GUARD_NAMES
    assert not any(registered.values())
    for stage in Stage:
        assert manager.guards_for_stage(stage) == []


@pytest.mark.parametrize("name", ["B", "C"])
def test_b_and_c_have_every_guard_enabled(name):
    manager = build_plugin_manager(load_condition(name))

    assert {rg.plugin.name for rg in manager.registry.all_guards() if rg.enabled} == GUARD_NAMES


def test_modes_per_condition():
    assert load_condition("B").policy.coordination_mode == CoordinationMode.INDEPENDENT
    assert load_condition("C").policy.coordination_mode == CoordinationMode.LINKED


def test_thresholds_and_weights_are_identical_across_conditions():
    """Only the mode / Guard on-off may differ, never the thresholds."""
    policies = [load_condition(n).policy for n in CONDITION_FILES]

    assert len({p.strict_threshold for p in policies}) == 1
    assert len({p.block_threshold for p in policies}) == 1
    assert all(p.guard_weights == policies[0].guard_weights for p in policies)
    assert all(p.critical_rule_ids == policies[0].critical_rule_ids for p in policies)


def test_each_condition_has_its_own_policy_version():
    versions = [load_condition(n).policy.policy_version for n in CONDITION_FILES]

    assert len(set(versions)) == len(versions)


def test_threshold_override_changes_policy_version():
    base = load_condition("C").policy
    swept = load_condition("C", block_threshold=0.92).policy

    assert swept.block_threshold == 0.92
    assert swept.policy_version != base.policy_version
    assert swept.policy_version.endswith("+block0.92")
    assert swept.strict_threshold == base.strict_threshold


def test_override_equal_to_file_value_keeps_policy_version():
    base = load_condition("C").policy

    assert load_condition("C", block_threshold=base.block_threshold).policy == base


def test_condition_security_factory_builds_an_orchestrator_with_the_condition_policy():
    from security.policy.conditions import make_condition_security_factory

    class _Sink:
        def record_result(self, result):
            pass

        def record_decision(self, decision):
            pass

    for name in CONDITION_FILES:
        condition = load_condition(name)
        orchestrator = make_condition_security_factory(condition, _Sink())(enforcement=None)
        try:
            assert orchestrator.policy_config == condition.policy
        finally:
            orchestrator.close()


@pytest.mark.parametrize("name", ["A", "B", "C"])
def test_condition_is_recoverable_from_policy_version(name):
    version = load_condition(name).policy.policy_version
    assert condition_from_policy_version(version) == name


@pytest.mark.parametrize("name", ["A", "B", "C"])
def test_condition_is_recoverable_with_threshold_override(name):
    version = load_condition(name, block_threshold=0.92).policy.policy_version
    assert version.endswith("+block0.92")
    assert condition_from_policy_version(version) == name


@pytest.mark.parametrize("version", ["", "v0.1.0", "v0.1.0-cond-d-adaptive", None])
def test_non_condition_policy_versions_give_none(version):
    assert condition_from_policy_version(version) is None
