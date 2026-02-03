"""Team management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_team_tools(mcp: FastMCP) -> None:
    """Register team management tools."""

    @mcp.tool(
        description="List all teams",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def list_teams(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all teams in Dependency Track.

        Teams are used for access control and organizing users.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/team", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "teams": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List visible teams",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def list_visible_teams(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List teams that are visible to the current user.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/team/visible", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "teams": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get a specific team by UUID",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def get_team(
        uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Get detailed information about a specific team.
        """
        try:
            client = get_client()
            data = await client.get(f"/team/{uuid}")
            return {"team": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get information about the current team",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def get_current_team() -> dict:
        """
        Get information about the team associated with the current API key.
        """
        try:
            client = get_client()
            data = await client.get("/team/self")
            return {"team": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new team",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def create_team(
        name: Annotated[str, Field(description="Team name")],
    ) -> dict:
        """
        Create a new team.

        After creating, use permission tools to assign permissions.
        """
        try:
            client = get_client()
            payload = {"name": name}

            data = await client.put("/team", data=payload)
            return {"team": data, "message": "Team created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update a team",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def update_team(
        uuid: Annotated[str, Field(description="Team UUID")],
        name: Annotated[str | None, Field(description="New team name")] = None,
    ) -> dict:
        """
        Update a team's properties.
        """
        try:
            client = get_client()

            # Get existing team
            existing = await client.get(f"/team/{uuid}")

            # Update fields
            if name is not None:
                existing["name"] = name

            data = await client.post("/team", data=existing)
            return {"team": data, "message": "Team updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a team",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def delete_team(
        uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Delete a team.

        Warning: This removes the team and all its API keys.
        """
        try:
            client = get_client()
            await client.delete("/team", params={"uuid": uuid})
            return {"message": f"Team {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Generate an API key for a team",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def generate_api_key(
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Generate a new API key for a team.

        Returns the new API key value. Store it securely as it cannot be retrieved again.
        """
        try:
            client = get_client()
            data = await client.put(f"/team/{team_uuid}/key")
            return {"apiKey": data, "message": "API key generated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Regenerate an API key",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def regenerate_api_key(
        key: Annotated[
            str, Field(description="API key public ID or key value to regenerate")
        ],
    ) -> dict:
        """
        Regenerate an existing API key.

        The old key is deleted and a new one is created.
        Returns the new API key value.
        """
        try:
            client = get_client()
            data = await client.post(f"/team/key/{key}")
            return {"apiKey": data, "message": "API key regenerated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete an API key",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def delete_api_key(
        key: Annotated[
            str, Field(description="API key public ID or key value to delete")
        ],
    ) -> dict:
        """
        Delete an API key.
        """
        try:
            client = get_client()
            await client.delete(f"/team/key/{key}")
            return {"message": "API key deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an API key's comment",
        tags=[Scopes.ADMIN_TEAMS],
    )
    async def update_api_key_comment(
        key: Annotated[str, Field(description="API key public ID or key value")],
        comment: Annotated[str, Field(description="New comment for the API key")],
    ) -> dict:
        """
        Update the comment/description for an API key.
        """
        try:
            client = get_client()
            data = await client.post(
                f"/team/key/{key}/comment", data={"comment": comment}
            )
            return {"apiKey": data, "message": "API key comment updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
