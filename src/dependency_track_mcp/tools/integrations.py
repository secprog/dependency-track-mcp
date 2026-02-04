"""Integration tools for Dependency Track."""

from fastmcp import FastMCP

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_integration_tools(mcp: FastMCP) -> None:
    """Register integration tools."""

    @mcp.tool(
        description="List all active OSV ecosystems",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def list_osv_ecosystems() -> dict:
        """
        List all active ecosystems available in OSV (Open Source Vulnerability) database.

        OSV provides vulnerability data for various package ecosystems.
        """
        try:
            client = get_client()
            data = await client.get("/integration/osv/ecosystem")
            return {"ecosystems": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List inactive OSV ecosystems available for activation",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def list_inactive_osv_ecosystems() -> dict:
        """
        List inactive OSV ecosystems that can be enabled.

        These ecosystems are available in OSV but not currently active.
        """
        try:
            client = get_client()
            data = await client.get("/integration/osv/ecosystem/inactive")
            return {"ecosystems": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
