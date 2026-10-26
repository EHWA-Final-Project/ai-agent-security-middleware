from pathlib import Path

import pytest
from pydantic import ValidationError

from security.policy.config import CoordinationMode, PolicyConfig, load_policy_config


def test_coordination_mode_defaults_to_linked():
    assert PolicyConfig(policy_version="v").coordination_mode == CoordinationMode.LINKED


def test_coordination_mode_loads_from_yaml(tmp_path):
    config_path = tmp_path / "policy.yaml"
    config_path.write_text(
        'policy_version: "v0.1.0-exp-independent"\ncoordination_mode: independent\n',
        encoding="utf-8",
    )

    policy = load_policy_config(config_path)

    assert policy.coordination_mode == CoordinationMode.INDEPENDENT


def test_shipped_example_policy_is_linked():
    example = Path(__file__).resolve().parents[2] / "src/security/policy/policy.example.yaml"

    assert load_policy_config(example).coordination_mode == CoordinationMode.LINKED


def test_unknown_coordination_mode_is_rejected():
    with pytest.raises(ValidationError):
        PolicyConfig(policy_version="v", coordination_mode="bogus")
