"""License group management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_license_group_tools(mcp: FastMCP) -> None:
    """Register license group management tools."""

    @mcp.tool(
        description="List all license groups",
        tags=[Scopes.READ_LICENSES],
    )
    async def list_license_groups(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all license groups.

        License groups are collections of licenses used for policy enforcement.
        For example, a "Permissive" group might contain MIT, Apache-2.0, etc.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/licenseGroup", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "licenseGroups": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get a specific license group by UUID",
        tags=[Scopes.READ_LICENSES],
    )
    async def get_license_group(
        uuid: Annotated[str, Field(description="License group UUID")],
    ) -> dict:
        """
        Get detailed information about a specific license group.

        Returns the group with all its member licenses.
        """
        try:
            client = get_client()
            data = await client.get(f"/licenseGroup/{uuid}")
            return {"licenseGroup": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new license group",
        tags=[Scopes.WRITE_LICENSES],
    )
    async def create_license_group(
        name: Annotated[str, Field(description="License group name")],
        risk_weight: Annotated[
            int, Field(ge=0, le=10, description="Risk weight for scoring (0-10)")
        ] = 5,
    ) -> dict:
        """
        Create a new license group.

        After creating, use add_license_to_group to add licenses.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "riskWeight": risk_weight,
            }

            data = await client.put("/licenseGroup", data=payload)
            return {"licenseGroup": data, "message": "License group created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing license group",
        tags=[Scopes.WRITE_LICENSES],
    )
    async def update_license_group(
        uuid: Annotated[str, Field(description="License group UUID")],
        name: Annotated[str | None, Field(description="New group name")] = None,
        risk_weight: Annotated[
            int | None, Field(ge=0, le=10, description="New risk weight (0-10)")
        ] = None,
    ) -> dict:
        """
        Update an existing license group.
        """
        try:
            client = get_client()

            # Get existing group
            existing = await client.get(f"/licenseGroup/{uuid}")

            # Update fields
            if name is not None:
                existing["name"] = name
            if risk_weight is not None:
                existing["riskWeight"] = risk_weight

            data = await client.post("/licenseGroup", data=existing)
            return {"licenseGroup": data, "message": "License group updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a license group",
        tags=[Scopes.WRITE_LICENSES],
    )
    async def delete_license_group(
        uuid: Annotated[str, Field(description="License group UUID")],
    ) -> dict:
        """
        Delete a license group.
        """
        try:
            client = get_client()
            await client.delete(f"/licenseGroup/{uuid}")
            return {"message": f"License group {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add a license to a license group",
        tags=[Scopes.WRITE_LICENSES],
    )
    async def add_license_to_group(
        group_uuid: Annotated[str, Field(description="License group UUID")],
        license_uuid: Annotated[str, Field(description="License UUID")],
    ) -> dict:
        """
        Add a license to a license group.
        """
        try:
            client = get_client()
            await client.post(f"/licenseGroup/{group_uuid}/license/{license_uuid}")
            return {"message": "License added to group successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a license from a license group",
        tags=[Scopes.WRITE_LICENSES],
    )
    async def remove_license_from_group(
        group_uuid: Annotated[str, Field(description="License group UUID")],
        license_uuid: Annotated[str, Field(description="License UUID")],
    ) -> dict:
        """
        Remove a license from a license group.
        """
        try:
            client = get_client()
            await client.delete(f"/licenseGroup/{group_uuid}/license/{license_uuid}")
            return {"message": "License removed from group successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
