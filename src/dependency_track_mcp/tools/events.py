"""Event and task processing tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_event_tools(mcp: FastMCP) -> None:
    """Register event and task processing tools."""

    @mcp.tool(
        description="Check if a task is still being processed",
        tags=[Scopes.SYSTEM_VERSION],
    )
    async def check_event_token(
        token: Annotated[str, Field(description="Event token UUID")],
    ) -> dict:
        """
        Check if a background task is still being processed.

        Returns whether the task associated with the given token is
        still in the processing queue or has completed.

        Useful for polling the status of BOM uploads, vulnerability
        analysis, and other async operations.
        """
        try:
            client = get_client()
            data = await client.get(f"/event/token/{token}")
            return {"event": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
