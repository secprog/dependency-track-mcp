"""Project property management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_project_property_tools(mcp: FastMCP) -> None:
    """Register project property tools."""

    @mcp.tool(
        description="List all properties for a project",
        tags=[Scopes.READ_PROJECTS],
    )
    async def list_project_properties(
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        List all custom properties for a specific project.

        Project properties are key-value pairs that can store
        additional metadata about a project.
        """
        try:
            client = get_client()
            data = await client.get(f"/project/{project_uuid}/property")
            return {"properties": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a project property",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def create_project_property(
        project_uuid: Annotated[str, Field(description="Project UUID")],
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
        Create a new project property.
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

            data = await client.put(f"/project/{project_uuid}/property", data=payload)
            return {"property": data, "message": "Project property created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update a project property",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def update_project_property(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        group_name: Annotated[str, Field(description="Property group name")],
        property_name: Annotated[str, Field(description="Property name")],
        property_value: Annotated[str, Field(description="New property value")],
        property_type: Annotated[
            str,
            Field(
                description="Property type: STRING, INTEGER, "
                "BOOLEAN, NUMBER, URL, UUID, ENCRYPTEDSTRING"
            ),
        ] = "STRING",
    ) -> dict:
        """
        Update an existing project property.
        """
        try:
            client = get_client()
            payload = {
                "groupName": group_name,
                "propertyName": property_name,
                "propertyValue": property_value,
                "propertyType": property_type,
            }

            data = await client.post(f"/project/{project_uuid}/property", data=payload)
            return {"property": data, "message": "Project property updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a project property",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def delete_project_property(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        group_name: Annotated[str, Field(description="Property group name")],
        property_name: Annotated[str, Field(description="Property name")],
    ) -> dict:
        """
        Delete a project property.
        """
        try:
            client = get_client()
            await client.delete(
                f"/project/{project_uuid}/property",
                params={"groupName": group_name, "propertyName": property_name},
            )
            return {"message": "Project property deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
