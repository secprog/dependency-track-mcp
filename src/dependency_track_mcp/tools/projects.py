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

    @mcp.tool(
        description="Get child projects filtered by classifier",
        tags=[Scopes.READ_PROJECTS],
    )
    async def get_project_children_by_classifier(
        uuid: Annotated[str, Field(description="Parent project UUID")],
        classifier: Annotated[
            str,
            Field(
                description="Project classifier: APPLICATION, FRAMEWORK, LIBRARY, CONTAINER, OPERATING_SYSTEM, DEVICE, FIRMWARE, FILE"
            ),
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get child projects of a parent project filtered by classifier.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/project/{uuid}/children/classifier/{classifier}", params=params
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

    @mcp.tool(
        description="Get child projects filtered by tag",
        tags=[Scopes.READ_PROJECTS],
    )
    async def get_project_children_by_tag(
        uuid: Annotated[str, Field(description="Parent project UUID")],
        tag: Annotated[str, Field(description="Tag to filter by")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get child projects of a parent project filtered by tag.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/project/{uuid}/children/tag/{tag}", params=params
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

    @mcp.tool(
        description="List projects filtered by classifier",
        tags=[Scopes.READ_PROJECTS],
    )
    async def list_projects_by_classifier(
        classifier: Annotated[
            str,
            Field(
                description="Project classifier: APPLICATION, FRAMEWORK, LIBRARY, CONTAINER, OPERATING_SYSTEM, DEVICE, FIRMWARE, FILE"
            ),
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all projects filtered by classifier type.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/project/classifier/{classifier}", params=params
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
        description="List projects filtered by tag",
        tags=[Scopes.READ_PROJECTS],
    )
    async def list_projects_by_tag(
        tag: Annotated[str, Field(description="Tag to filter by")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all projects that have the specified tag.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/project/tag/{tag}", params=params
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
        description="Get the latest version of a project by name",
        tags=[Scopes.READ_PROJECTS],
    )
    async def get_latest_project_version(
        name: Annotated[str, Field(description="Project name")],
    ) -> dict:
        """
        Get the latest version of a project by its name.

        Returns the most recent version of the project based on version ordering.
        """
        try:
            client = get_client()
            data = await client.get(f"/project/latest/{name}")
            return {"project": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Clone an existing project",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def clone_project(
        uuid: Annotated[str, Field(description="Project UUID to clone")],
        version: Annotated[str, Field(description="Version for the cloned project")],
        include_tags: Annotated[
            bool, Field(description="Include tags in the clone")
        ] = True,
        include_properties: Annotated[
            bool, Field(description="Include properties in the clone")
        ] = True,
        include_components: Annotated[
            bool, Field(description="Include components in the clone")
        ] = True,
        include_services: Annotated[
            bool, Field(description="Include services in the clone")
        ] = True,
        include_audit_history: Annotated[
            bool, Field(description="Include audit history in the clone")
        ] = False,
        include_acl: Annotated[
            bool, Field(description="Include ACL in the clone")
        ] = True,
        include_policy_violations: Annotated[
            bool, Field(description="Include policy violations in the clone")
        ] = False,
    ) -> dict:
        """
        Clone an existing project with a new version.

        Creates a copy of the project with customizable inclusion of
        components, tags, properties, and other data.
        """
        try:
            client = get_client()
            payload = {
                "project": uuid,
                "version": version,
                "includeTags": include_tags,
                "includeProperties": include_properties,
                "includeComponents": include_components,
                "includeServices": include_services,
                "includeAuditHistory": include_audit_history,
                "includeACL": include_acl,
                "includePolicyViolations": include_policy_violations,
            }

            data = await client.put("/project/clone", data=payload)
            return {"project": data, "message": "Project cloned successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Batch delete multiple projects",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def batch_delete_projects(
        uuids: Annotated[list[str], Field(description="List of project UUIDs to delete")],
    ) -> dict:
        """
        Delete multiple projects at once.

        Warning: This permanently removes the projects and all associated data.
        """
        try:
            client = get_client()
            await client.post("/project/batchDelete", data=uuids)
            return {"message": f"Successfully deleted {len(uuids)} projects"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Partially update a project using PATCH",
        tags=[Scopes.WRITE_PROJECTS],
    )
    async def patch_project(
        uuid: Annotated[str, Field(description="Project UUID to update")],
        name: Annotated[str | None, Field(description="New project name")] = None,
        version: Annotated[str | None, Field(description="New project version")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        active: Annotated[bool | None, Field(description="Set active status")] = None,
        classifier: Annotated[str | None, Field(description="New classifier")] = None,
        tags: Annotated[
            list[str] | None, Field(description="New list of tags")
        ] = None,
    ) -> dict:
        """
        Partially update a project using PATCH method.

        Only the fields that are provided will be updated.
        More efficient than full update when changing few fields.
        """
        try:
            client = get_client()
            payload = {}

            if name is not None:
                payload["name"] = name
            if version is not None:
                payload["version"] = version
            if description is not None:
                payload["description"] = description
            if active is not None:
                payload["active"] = active
            if classifier is not None:
                payload["classifier"] = classifier
            if tags is not None:
                payload["tags"] = [{"name": t} for t in tags]

            data = await client.patch(f"/project/{uuid}", data=payload)
            return {"project": data, "message": "Project patched successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List projects excluding descendants of a specific project",
        tags=[Scopes.READ_PROJECTS],
    )
    async def list_projects_without_descendants(
        uuid: Annotated[str, Field(description="Project UUID to exclude descendants of")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all projects excluding descendants of the specified project.

        Useful when selecting a parent project to avoid circular references.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/project/withoutDescendantsOf/{uuid}", params=params
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
