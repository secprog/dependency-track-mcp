"""Test utilities for FastMCP tool discovery."""

from __future__ import annotations

from typing import Iterable, Any


def _normalize_tools(tools: Any) -> list[Any]:
    if tools is None:
        return []
    if isinstance(tools, dict):
        return list(tools.values())
    if isinstance(tools, (list, tuple, set)):
        return list(tools)
    return []


def get_registered_tools(mcp) -> list[Any]:
    """Return registered tools for a FastMCP instance.

    Handles different FastMCP internal registries across versions.
    """
    if hasattr(mcp, "_tool_manager"):
        manager = getattr(mcp, "_tool_manager")
        if hasattr(manager, "_tools"):
            tools = _normalize_tools(getattr(manager, "_tools"))
            if tools:
                return tools

    for attr in (
        "tools",
        "_tools",
        "tool_registry",
        "_tool_registry",
        "registry",
        "_registry",
    ):
        if hasattr(mcp, attr):
            value = getattr(mcp, attr)
            if callable(value):
                try:
                    value = value()
                except TypeError:
                    pass
            tools = _normalize_tools(value)
            if tools:
                return tools

    for value in mcp.__dict__.values():
        tools = _normalize_tools(value)
        if tools and hasattr(tools[0], "name"):
            return tools

    return []


def find_tool(mcp, name: str):
    """Find a tool by name from a FastMCP instance."""
    for tool in get_registered_tools(mcp):
        if getattr(tool, "name", None) == name or getattr(tool, "key", None) == name:
            return tool
    return None
