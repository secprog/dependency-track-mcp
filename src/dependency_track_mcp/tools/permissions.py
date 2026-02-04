"""Permission management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_permission_tools(mcp: FastMCP) -> None:
    """Register permission management tools."""

    @mcp.tool(
        description="List all available permissions",
        tags=[Scopes.WRITE_PERMISSIONS],
    )
    async def list_permissions() -> dict:
        """
        List all available permissions in Dependency Track.

        Permissions define what actions users and teams can perform.
        """
        try:
            client = get_client()
            data = await client.get("/permission")
            return {"permissions": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add a permission to a team",
        tags=[Scopes.READ_PERMISSIONS],
    )
    async def add_permission_to_team(
        permission: Annotated[
            str,
            Field(
                description="Permission name (e.g., BOM_UPLOAD, "
                "VULNERABILITY_ANALYSIS, PROJECT_CREATION_UPLOAD)"
            ),
        ],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Add a permission to a team.

        All users in the team will have this permission.
        """
        try:
            client = get_client()
            await client.post(f"/permission/{permission}/team/{team_uuid}")
            return {"message": f"Permission {permission} added to team successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a permission from a team",
        tags=[Scopes.WRITE_PERMISSIONS],
    )
    async def remove_permission_from_team(
        permission: Annotated[str, Field(description="Permission name")],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Remove a permission from a team.
        """
        try:
            client = get_client()
            await client.delete(f"/permission/{permission}/team/{team_uuid}")
            return {"message": f"Permission {permission} removed from team successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add a permission to a user",
        tags=[Scopes.WRITE_PERMISSIONS],
    )
    async def add_permission_to_user(
        permission: Annotated[str, Field(description="Permission name")],
        username: Annotated[str, Field(description="Username")],
    ) -> dict:
        """
        Add a permission directly to a user.

        User-level permissions supplement team permissions.
        """
        try:
            client = get_client()
            await client.post(f"/permission/{permission}/user/{username}")
            return {"message": f"Permission {permission} added to user successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a permission from a user",
        tags=[Scopes.WRITE_PERMISSIONS],
    )
    async def remove_permission_from_user(
        permission: Annotated[str, Field(description="Permission name")],
        username: Annotated[str, Field(description="Username")],
    ) -> dict:
        """
        Remove a permission from a user.
        """
        try:
            client = get_client()
            await client.delete(f"/permission/{permission}/user/{username}")
            return {"message": f"Permission {permission} removed from user successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
