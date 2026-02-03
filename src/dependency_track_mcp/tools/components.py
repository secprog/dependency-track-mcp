"""Component management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_component_tools(mcp: FastMCP) -> None:
    """Register component management tools."""

    @mcp.tool(
        description="List all components in a project",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def list_project_components(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all components in a project.

        Returns components with their metadata including name, version,
        Package URL (PURL), license information, and hashes.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/component/project/{project_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "components": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get detailed information about a specific component",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def get_component(
        uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        Get detailed information about a specific component.

        Returns full component metadata including PURL, CPE, license,
        and hash information.
        """
        try:
            client = get_client()
            data = await client.get(f"/component/{uuid}")
            return {"component": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Find components by Package URL (PURL)",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def find_component_by_purl(
        purl: Annotated[
            str, Field(description="Package URL (e.g., pkg:npm/lodash@4.17.21)")
        ],
    ) -> dict:
        """
        Find components by their Package URL (PURL).

        PURL is a standardized way to identify software components.
        Example: pkg:npm/lodash@4.17.21
        """
        try:
            client = get_client()
            data = await client.get("/component/identity", params={"purl": purl})
            return {"components": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Find components by hash (MD5, SHA-1, SHA-256, or SHA-512)",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def find_component_by_hash(
        hash_value: Annotated[str, Field(description="Hash value to search for")],
    ) -> dict:
        """
        Find components by their file hash.

        Supports MD5, SHA-1, SHA-256, and SHA-512 hashes.
        Useful for identifying components from binary analysis.
        """
        try:
            client = get_client()
            data = await client.get("/component/hash/{hash_value}")
            return {"components": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get the dependency graph for a project",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def get_dependency_graph(
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Get the dependency graph for a project.

        Returns the hierarchical relationship between components,
        showing direct and transitive dependencies.
        """
        try:
            client = get_client()
            data = await client.get(f"/dependencyGraph/project/{project_uuid}/directDependencies")
            return {"graph": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new component in a project",
        tags=[Scopes.WRITE_COMPONENTS],
    )
    async def create_component(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        name: Annotated[str, Field(description="Component name")],
        version: Annotated[str | None, Field(description="Component version")] = None,
        group: Annotated[str | None, Field(description="Component group/namespace")] = None,
        purl: Annotated[
            str | None,
            Field(description="Package URL (e.g., pkg:npm/lodash@4.17.21)"),
        ] = None,
        cpe: Annotated[str | None, Field(description="CPE identifier")] = None,
        description: Annotated[str | None, Field(description="Component description")] = None,
        license_name: Annotated[
            str | None, Field(description="License name or SPDX ID")
        ] = None,
        classifier: Annotated[
            str | None,
            Field(
                description="Component classifier: APPLICATION, FRAMEWORK, LIBRARY, CONTAINER, OPERATING_SYSTEM, DEVICE, FIRMWARE, FILE"
            ),
        ] = None,
    ) -> dict:
        """
        Create a new component in a project.

        Components represent software dependencies with metadata like
        name, version, PURL, license, and hashes.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "project": project_uuid,
            }

            if version:
                payload["version"] = version
            if group:
                payload["group"] = group
            if purl:
                payload["purl"] = purl
            if cpe:
                payload["cpe"] = cpe
            if description:
                payload["description"] = description
            if license_name:
                payload["license"] = license_name
            if classifier:
                payload["classifier"] = classifier

            data = await client.put(f"/component/project/{project_uuid}", data=payload)
            return {"component": data, "message": "Component created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing component",
        tags=[Scopes.WRITE_COMPONENTS],
    )
    async def update_component(
        uuid: Annotated[str, Field(description="Component UUID")],
        name: Annotated[str | None, Field(description="New component name")] = None,
        version: Annotated[str | None, Field(description="New component version")] = None,
        group: Annotated[str | None, Field(description="New component group")] = None,
        purl: Annotated[str | None, Field(description="New Package URL")] = None,
        cpe: Annotated[str | None, Field(description="New CPE identifier")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        license_name: Annotated[str | None, Field(description="New license")] = None,
    ) -> dict:
        """
        Update an existing component's properties.

        Performs a partial update - only provided fields are modified.
        """
        try:
            client = get_client()

            # First get the existing component
            existing = await client.get(f"/component/{uuid}")

            # Update only provided fields
            if name is not None:
                existing["name"] = name
            if version is not None:
                existing["version"] = version
            if group is not None:
                existing["group"] = group
            if purl is not None:
                existing["purl"] = purl
            if cpe is not None:
                existing["cpe"] = cpe
            if description is not None:
                existing["description"] = description
            if license_name is not None:
                existing["license"] = license_name

            data = await client.post("/component", data=existing)
            return {"component": data, "message": "Component updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a component from a project",
        tags=[Scopes.WRITE_COMPONENTS],
    )
    async def delete_component(
        uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        Delete a component from Dependency Track.

        Warning: This permanently removes the component and its associated data.
        """
        try:
            client = get_client()
            await client.delete(f"/component/{uuid}")
            return {"message": f"Component {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get the expanded dependency graph for specific components",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def get_component_dependency_graph(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        component_uuids: Annotated[
            list[str], Field(description="List of component UUIDs to expand")
        ],
    ) -> dict:
        """
        Get the expanded dependency graph showing all occurrences of specific components.

        Returns the hierarchical relationship between components,
        showing where each specified component appears in the dependency tree.
        """
        try:
            client = get_client()
            uuids_param = ",".join(component_uuids)
            data = await client.get(
                f"/component/project/{project_uuid}/dependencyGraph/{uuids_param}"
            )
            return {"graph": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Request identification of internal components in the portfolio",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def identify_internal_components() -> dict:
        """
        Request identification of internal components across the portfolio.

        Triggers a background process to identify components that are
        internal to the organization based on configured rules.
        """
        try:
            client = get_client()
            await client.get("/component/internal/identify")
            return {"message": "Internal component identification initiated"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get direct dependencies of a specific component",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def get_component_direct_dependencies(
        component_uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        Get direct dependencies of a specific component.

        Returns the immediate children in the dependency graph.
        """
        try:
            client = get_client()
            data = await client.get(
                f"/dependencyGraph/component/{component_uuid}/directDependencies"
            )
            return {"dependencies": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
