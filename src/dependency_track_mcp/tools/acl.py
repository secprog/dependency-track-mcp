"""Access Control List (ACL) management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_acl_tools(mcp: FastMCP) -> None:
    """Register ACL management tools."""

    @mcp.tool(
        description="Get projects assigned to a team via ACL",
        tags=[Scopes.ADMIN_ACL],
    )
    async def get_team_acl_projects(
        team_uuid: Annotated[str, Field(description="Team UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get the projects assigned to a team via ACL mappings.

        ACL mappings restrict which projects a team can access when
        portfolio access control is enabled.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/acl/team/{team_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "projects": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add an ACL mapping between a team and project",
        tags=[Scopes.ADMIN_ACL],
    )
    async def add_acl_mapping(
        team_uuid: Annotated[str, Field(description="Team UUID")],
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Add an ACL mapping to grant a team access to a project.

        ACL mappings are used when portfolio access control is enabled
        to restrict which projects teams can view and modify.
        """
        try:
            client = get_client()
            payload = {
                "team": team_uuid,
                "project": project_uuid,
            }

            await client.put("/acl/mapping", data=payload)
            return {"message": "ACL mapping created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove an ACL mapping between a team and project",
        tags=[Scopes.ADMIN_ACL],
    )
    async def remove_acl_mapping(
        team_uuid: Annotated[str, Field(description="Team UUID")],
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Remove an ACL mapping between a team and project.

        This revokes the team's access to the project.
        """
        try:
            client = get_client()
            await client.delete(f"/acl/mapping/team/{team_uuid}/project/{project_uuid}")
            return {"message": "ACL mapping removed successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
