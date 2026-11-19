"""Tool-name helpers for MCP ``server/tool`` names."""

import pytest

from security.plugins.guards._tool_names import base_tool_name, is_qualified


@pytest.mark.parametrize(
    ("name", "base", "qualified"),
    [
        ("demo/read_file", "read_file", True),
        ("demo/send_email", "send_email", True),
        ("read_file", "read_file", False),  # bare names are unchanged
        ("a/b/send_email", "send_email", True),  # last segment is the tool
        ("demo/", "", True),
        ("", "", False),
    ],
)
def test_base_tool_name_and_is_qualified(name, base, qualified):
    assert base_tool_name(name) == base
    assert is_qualified(name) is qualified


@pytest.mark.parametrize("value", [None, 5, ["demo/read_file"]])
def test_non_string_names_pass_through(value):
    assert base_tool_name(value) == value
    assert is_qualified(value) is False
