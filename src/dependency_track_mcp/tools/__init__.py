"""Dependency Track MCP Tools."""

from dependency_track_mcp.tools.projects import register_project_tools
from dependency_track_mcp.tools.components import register_component_tools
from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools
from dependency_track_mcp.tools.findings import register_finding_tools
from dependency_track_mcp.tools.metrics import register_metrics_tools
from dependency_track_mcp.tools.policies import register_policy_tools
from dependency_track_mcp.tools.bom import register_bom_tools
from dependency_track_mcp.tools.search import register_search_tools


def register_all_tools(mcp):
    """Register all Dependency Track tools with the MCP server."""
    register_project_tools(mcp)
    register_component_tools(mcp)
    register_vulnerability_tools(mcp)
    register_finding_tools(mcp)
    register_metrics_tools(mcp)
    register_policy_tools(mcp)
    register_bom_tools(mcp)
    register_search_tools(mcp)
