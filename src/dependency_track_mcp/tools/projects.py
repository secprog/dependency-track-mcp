"""Project management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_project_tools(mcp: FastMCP) -> None:
    """Register project management tools."""

    @mcp.tool(
        description="List all projects in Dependency Track with optional filtering and pagination",
        tags=[Scopes.READ_PROJECTS],
    )
    async def list_projects(
        name: Annotated[str | None, Field(description="Filter by project name")] = None,
        tag: Annotated[str | None, Field(description="Filter by tag")] = None,
        active: Annotated[
            bool | None, Field(description="Filter by active status")
        ] = None,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all projects in Dependency Track.

        Returns a paginated list of projects with their metadata including
        name, version, tags, and risk scores.
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
            }
            if name:
                params["name"] = name
            if tag:
                params["tag"] = tag
            if active is not None:
                params["active"] = str(active).lower()

            data, headers = await client.get_with_headers("/project", params=params)
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
        description="Get detailed information about a specific project by UUID",
        tags=[Scopes.READ_PROJECTS],
    )
    async def get_project(
        uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Get detailed information about a specific project.

        Returns project metadata including components count, vulnerability metrics,
        and last BOM import information.
        """
        try:
            client = get_client()
            data = await client.get(f"/project/{uuid}")
            return {"project": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Look up a project by name and version",
        tags=[Scopes.READ_PROJECTS],
    )
    async def lookup_project(
        name: Annotated[str, Field(description="Project name")],
        version: Annotated[str, Field(description="Project version")],
    ) -> dict:
        """
        Look up a project by its name and version combination.

        Useful when you know the project name and version but not the UUID.
        """
        try:
            client = get_client()
            params = {"name": name, "version": version}
            data = await client.get("/project/lookup", params=params)
            return {"project": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new project in Dependency Track",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def create_project(
        name: Annotated[str, Field(description="Project name")],
        version: Annotated[
            str | None, Field(description="Project version")
        ] = None,
        description: Annotated[
            str | None, Field(description="Project description")
        ] = None,
        classifier: Annotated[
            str | None,
            Field(
                description="Project classifier (APPLICATION, FRAMEWORK, LIBRARY, CONTAINER, OPERATING_SYSTEM, DEVICE, FIRMWARE, FILE)"
            ),
        ] = None,
        tags: Annotated[
            list[str] | None, Field(description="List of tags to assign")
        ] = None,
        parent_uuid: Annotated[
            str | None, Field(description="Parent project UUID for hierarchy")
        ] = None,
    ) -> dict:
        """
        Create a new project in Dependency Track.

        Projects are the top-level organizational unit for tracking
        components and their vulnerabilities.
        """
        try:
            client = get_client()
            payload = {"name": name, "active": True}

            if version:
                payload["version"] = version
            if description:
                payload["description"] = description
            if classifier:
                payload["classifier"] = classifier
            if tags:
                payload["tags"] = [{"name": t} for t in tags]
            if parent_uuid:
                payload["parent"] = {"uuid": parent_uuid}

            data = await client.put("/project", data=payload)
            return {"project": data, "message": "Project created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing project",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def update_project(
        uuid: Annotated[str, Field(description="Project UUID to update")],
        name: Annotated[str | None, Field(description="New project name")] = None,
        version: Annotated[
            str | None, Field(description="New project version")
        ] = None,
        description: Annotated[
            str | None, Field(description="New description")
        ] = None,
        active: Annotated[
            bool | None, Field(description="Set active status")
        ] = None,
        tags: Annotated[
            list[str] | None, Field(description="New list of tags (replaces existing)")
        ] = None,
    ) -> dict:
        """
        Update an existing project's properties.

        Note: This performs a partial update. Only provided fields are modified.
        """
        try:
            client = get_client()

            # First get the existing project
            existing = await client.get(f"/project/{uuid}")

            # Update only provided fields
            if name is not None:
                existing["name"] = name
            if version is not None:
                existing["version"] = version
            if description is not None:
                existing["description"] = description
            if active is not None:
                existing["active"] = active
            if tags is not None:
                existing["tags"] = [{"name": t} for t in tags]

            data = await client.post("/project", data=existing)
            return {"project": data, "message": "Project updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a project from Dependency Track",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def delete_project(
        uuid: Annotated[str, Field(description="Project UUID to delete")],
    ) -> dict:
        """
        Delete a project from Dependency Track.

        Warning: This permanently removes the project and all associated data
        including components, vulnerabilities, and audit history.
        """
        try:
            client = get_client()
            await client.delete(f"/project/{uuid}")
            return {"message": f"Project {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get all child projects of a parent project",
        tags=[Scopes.READ_PROJECTS],
    )
    async def get_project_children(
        uuid: Annotated[str, Field(description="Parent project UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get child projects of a parent project.

        Useful for navigating project hierarchies.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/project/{uuid}/children", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "children": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
