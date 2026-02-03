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
        description="Get all projects that use a specific component",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def get_component_projects(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get all projects that use a specific component.

        Useful for understanding the impact of a vulnerable component
        across your portfolio.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/component/{component_uuid}/project", params=params
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
