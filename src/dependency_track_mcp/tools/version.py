"""Version and system information tools for Dependency Track."""

from fastmcp import FastMCP

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_version_tools(mcp: FastMCP) -> None:
    """Register version and system tools."""

    @mcp.tool(
        description="Get Dependency Track application version information",
        tags=[Scopes.SYSTEM_VERSION],
    )
    async def get_version() -> dict:
        """
        Get the Dependency Track application version information.

        Returns the application name, version, and build timestamp.
        """
        try:
            client = get_client()
            # Version endpoint is at /api/version, not under /api/v1
            # Use /../version to go up from /api/v1 to /api/version
            data = await client.get("/../version")
            return {"version": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
        except Exception as e:
            return {"error": str(e)}
