"""Version and system information tools for Dependency Track."""

import httpx
from fastmcp import FastMCP

from dependency_track_mcp.config import get_settings
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
            settings = get_settings()
            # Version endpoint is at /api/version, not under /api/v1
            async with httpx.AsyncClient(
                headers={
                    "X-Api-Key": settings.api_key,
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(settings.timeout),
                verify=settings.verify_ssl,
            ) as http_client:
                response = await http_client.get(f"{settings.url}/api/version")
                response.raise_for_status()
                return {"version": response.json()}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
        except Exception as e:
            return {"error": str(e)}
