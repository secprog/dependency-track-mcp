"""OpenID Connect (OIDC) integration tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_oidc_tools(mcp: FastMCP) -> None:
    """Register OIDC integration tools."""

    @mcp.tool(
        description="Check if OpenID Connect is available",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def oidc_available() -> dict:
        """
        Check if OpenID Connect is available and configured.
        """
        try:
            client = get_client()
            data = await client.get("/oidc/available")
            return {"available": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List all OIDC groups",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def list_oidc_groups(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all OIDC groups configured in Dependency Track.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/oidc/group", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "groups": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create an OIDC group",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def create_oidc_group(
        name: Annotated[str, Field(description="OIDC group name (must match claim value)")],
    ) -> dict:
        """
        Create a new OIDC group.

        The group name must match the group/role claim value from the identity provider.
        """
        try:
            client = get_client()
            payload = {"name": name}

            data = await client.put("/oidc/group", data=payload)
            return {"group": data, "message": "OIDC group created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an OIDC group",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def update_oidc_group(
        uuid: Annotated[str, Field(description="Group UUID")],
        name: Annotated[str, Field(description="New group name")],
    ) -> dict:
        """
        Update an OIDC group's name.
        """
        try:
            client = get_client()
            payload = {"uuid": uuid, "name": name}

            data = await client.post("/oidc/group", data=payload)
            return {"group": data, "message": "OIDC group updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete an OIDC group",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def delete_oidc_group(
        uuid: Annotated[str, Field(description="Group UUID")],
    ) -> dict:
        """
        Delete an OIDC group.
        """
        try:
            client = get_client()
            await client.delete(f"/oidc/group/{uuid}")
            return {"message": f"OIDC group {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get teams associated with an OIDC group",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def get_oidc_group_teams(
        group_uuid: Annotated[str, Field(description="OIDC group UUID")],
    ) -> dict:
        """
        Get teams mapped to a specific OIDC group.
        """
        try:
            client = get_client()
            data = await client.get(f"/oidc/group/{group_uuid}/team")
            return {"teams": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Map an OIDC group to a team",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def add_oidc_mapping(
        group_uuid: Annotated[str, Field(description="OIDC group UUID")],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Map an OIDC group to a team.

        Users in the OIDC group will be automatically added to the team.
        """
        try:
            client = get_client()
            payload = {
                "group": group_uuid,
                "team": team_uuid,
            }

            data = await client.put("/oidc/mapping", data=payload)
            return {"mapping": data, "message": "OIDC mapping created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove an OIDC group-to-team mapping",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def remove_oidc_mapping(
        mapping_uuid: Annotated[str, Field(description="Mapping UUID")],
    ) -> dict:
        """
        Remove an OIDC group-to-team mapping.
        """
        try:
            client = get_client()
            await client.delete(f"/oidc/mapping/{mapping_uuid}")
            return {"message": f"OIDC mapping {mapping_uuid} removed successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove an OIDC group-to-team mapping by group and team",
        tags=[Scopes.ADMIN_OIDC],
    )
    async def remove_oidc_group_team_mapping(
        group_uuid: Annotated[str, Field(description="OIDC group UUID")],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Remove a specific OIDC group-to-team mapping by group and team UUID.
        """
        try:
            client = get_client()
            await client.delete(f"/oidc/group/{group_uuid}/team/{team_uuid}/mapping")
            return {"message": "OIDC group-team mapping removed successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
