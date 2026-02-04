"""Component property management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_component_property_tools(mcp: FastMCP) -> None:
    """Register component property tools."""

    @mcp.tool(
        description="List all properties for a component",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def list_component_properties(
        component_uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        List all custom properties for a specific component.

        Component properties are key-value pairs that can store
        additional metadata about a component.
        """
        try:
            client = get_client()
            data = await client.get(f"/component/{component_uuid}/property")
            return {"properties": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a component property",
        tags=[Scopes.WRITE_COMPONENTS],
    )
    async def create_component_property(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        group_name: Annotated[str, Field(description="Property group name")],
        property_name: Annotated[str, Field(description="Property name")],
        property_value: Annotated[str, Field(description="Property value")],
        property_type: Annotated[
            str,
            Field(
                description="Property type: STRING, INTEGER, "
                "BOOLEAN, NUMBER, URL, UUID, ENCRYPTEDSTRING"
            ),
        ] = "STRING",
        description: Annotated[str | None, Field(description="Property description")] = None,
    ) -> dict:
        """
        Create a new component property.
        """
        try:
            client = get_client()
            payload = {
                "groupName": group_name,
                "propertyName": property_name,
                "propertyValue": property_value,
                "propertyType": property_type,
            }

            if description:
                payload["description"] = description

            data = await client.put(f"/component/{component_uuid}/property", data=payload)
            return {"property": data, "message": "Component property created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a component property",
        tags=[Scopes.WRITE_COMPONENTS],
    )
    async def delete_component_property(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        property_uuid: Annotated[str, Field(description="Property UUID")],
    ) -> dict:
        """
        Delete a component property.
        """
        try:
            client = get_client()
            await client.delete(f"/component/{component_uuid}/property/{property_uuid}")
            return {"message": "Component property deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
