"""LDAP integration tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_ldap_tools(mcp: FastMCP) -> None:
    """Register LDAP integration tools."""

    @mcp.tool(
        description="List all accessible LDAP groups",
        tags=[Scopes.WRITE_LDAP],
    )
    async def list_ldap_groups(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List the DNs of all accessible groups within the LDAP directory.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/ldap/groups", params=params)
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
        description="Get LDAP groups mapped to a team",
        tags=[Scopes.READ_LDAP],
    )
    async def get_team_ldap_groups(
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Get the LDAP group DNs mapped to a specific team.
        """
        try:
            client = get_client()
            data = await client.get(f"/ldap/team/{team_uuid}")
            return {"mappings": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add an LDAP group mapping to a team",
        tags=[Scopes.READ_LDAP],
    )
    async def add_ldap_mapping(
        team_uuid: Annotated[str, Field(description="Team UUID")],
        dn: Annotated[str, Field(description="LDAP group DN")],
    ) -> dict:
        """
        Map an LDAP group to a team.

        Users in the LDAP group will be automatically added to the team.
        """
        try:
            client = get_client()
            payload = {
                "team": team_uuid,
                "dn": dn,
            }

            data = await client.put("/ldap/mapping", data=payload)
            return {"mapping": data, "message": "LDAP mapping created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove an LDAP group mapping",
        tags=[Scopes.WRITE_LDAP],
    )
    async def remove_ldap_mapping(
        mapping_uuid: Annotated[str, Field(description="Mapping UUID")],
    ) -> dict:
        """
        Remove an LDAP group-to-team mapping.
        """
        try:
            client = get_client()
            await client.delete(f"/ldap/mapping/{mapping_uuid}")
            return {"message": f"LDAP mapping {mapping_uuid} removed successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
