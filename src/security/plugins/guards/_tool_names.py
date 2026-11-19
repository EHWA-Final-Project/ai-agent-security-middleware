"""Tool-name helpers for MCP-style qualified names (``server/tool``).

A qualified name such as ``demo/read_file`` names a tool on one MCP server.
Guards that classify a tool by its *kind* (sensitive tool, which output key to
scan) use the base name (``read_file``). Authorization (``allowed_tools``)
always compares the full qualified name, so ``evil/read_file`` is never
allowed just because ``demo/read_file`` is.

Names without a ``/`` are returned unchanged, so existing behavior for bare
tool names does not change.
"""

from __future__ import annotations

from typing import Any

_SEPARATOR = "/"


def is_qualified(tool_name: Any) -> bool:
    """True for ``server/tool`` style names."""
    return isinstance(tool_name, str) and _SEPARATOR in tool_name


def base_tool_name(tool_name: Any) -> Any:
    """``demo/read_file`` -> ``read_file``; bare names and non-strings pass through."""
    if is_qualified(tool_name):
        return tool_name.rsplit(_SEPARATOR, 1)[-1]
    return tool_name
