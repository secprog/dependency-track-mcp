"""Configuration property management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_config_property_tools(mcp: FastMCP) -> None:
    """Register configuration property tools."""

    @mcp.tool(
        description="List all configuration properties",
        tags=[Scopes.ADMIN_CONFIG],
    )
    async def list_config_properties() -> dict:
        """
        List all configuration properties.

        Returns system-wide configuration settings for Dependency Track.
        """
        try:
            client = get_client()
            data = await client.get("/configProperty")
            return {"properties": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get a public configuration property",
        tags=[Scopes.ADMIN_CONFIG],
    )
    async def get_public_config_property(
        group_name: Annotated[str, Field(description="Property group name")],
        property_name: Annotated[str, Field(description="Property name")],
    ) -> dict:
        """
        Get a public configuration property value.

        Public properties are accessible without admin permissions.
        """
        try:
            client = get_client()
            data = await client.get(
                f"/configProperty/public/{group_name}/{property_name}"
            )
            return {"property": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update a configuration property",
        tags=[Scopes.ADMIN_CONFIG],
    )
    async def update_config_property(
        group_name: Annotated[str, Field(description="Property group name")],
        property_name: Annotated[str, Field(description="Property name")],
        property_value: Annotated[str, Field(description="New property value")],
    ) -> dict:
        """
        Update a system configuration property.

        Warning: Changing configuration can affect system behavior.
        """
        try:
            client = get_client()
            payload = {
                "groupName": group_name,
                "propertyName": property_name,
                "propertyValue": property_value,
            }

            data = await client.post("/configProperty", data=payload)
            return {"property": data, "message": "Config property updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update multiple configuration properties at once",
        tags=[Scopes.ADMIN_CONFIG],
    )
    async def update_config_properties_batch(
        properties: Annotated[
            list[dict],
            Field(
                description="List of properties to update. "                "Each needs groupName, propertyName, propertyValue."
            ),
        ],
    ) -> dict:
        """
        Update multiple configuration properties in a single operation.

        Each property in the list should have:
        - groupName: Property group
        - propertyName: Property name
        - propertyValue: New value
        """
        try:
            client = get_client()
            data = await client.post("/configProperty/aggregate", data=properties)
            return {"properties": data, "message": "Config properties updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
