"""Repository management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_repository_tools(mcp: FastMCP) -> None:
    """Register repository management tools."""

    @mcp.tool(
        description="List all configured repositories",
        tags=[Scopes.READ_REPOSITORIES],
    )
    async def list_repositories(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all configured package repositories.

        Repositories are used for version resolution and vulnerability analysis.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/repository", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "repositories": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List repositories by type",
        tags=[Scopes.READ_REPOSITORIES],
    )
    async def list_repositories_by_type(
        repo_type: Annotated[
            str,
            Field(
                description="Repository type: CARGO, COMPOSER, "                "CPAN, GEM, GO_MODULES, HEX, MAVEN, NPM, "                "NUGET, PYPI, HACKAGE, GITHUB, NIX"
            ),
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List repositories that support a specific package type.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/repository/{repo_type}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "repositories": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new repository",
        tags=[Scopes.WRITE_REPOSITORIES],
    )
    async def create_repository(
        repo_type: Annotated[
            str,
            Field(
                description="Repository type: CARGO, COMPOSER, "                "CPAN, GEM, GO_MODULES, HEX, MAVEN, NPM, "                "NUGET, PYPI, HACKAGE, GITHUB, NIX"
            ),
        ],
        identifier: Annotated[str, Field(description="Repository identifier/name")],
        url: Annotated[str, Field(description="Repository URL")],
        resolution_order: Annotated[
            int, Field(ge=1, description="Resolution priority (lower = higher priority)")
        ] = 1,
        enabled: Annotated[bool, Field(description="Whether repository is enabled")] = True,
        internal: Annotated[
            bool, Field(description="Whether this is an internal/private repository")
        ] = False,
        username: Annotated[str | None, Field(description="Authentication username")] = None,
        password: Annotated[str | None, Field(description="Authentication password")] = None,
    ) -> dict:
        """
        Create a new package repository configuration.

        Repositories are used for version resolution and component metadata retrieval.
        """
        try:
            client = get_client()
            payload = {
                "type": repo_type,
                "identifier": identifier,
                "url": url,
                "resolutionOrder": resolution_order,
                "enabled": enabled,
                "internal": internal,
            }

            if username:
                payload["username"] = username
            if password:
                payload["password"] = password

            data = await client.put("/repository", data=payload)
            return {"repository": data, "message": "Repository created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing repository",
        tags=[Scopes.WRITE_REPOSITORIES],
    )
    async def update_repository(
        uuid: Annotated[str, Field(description="Repository UUID")],
        identifier: Annotated[str | None, Field(description="New identifier")] = None,
        url: Annotated[str | None, Field(description="New URL")] = None,
        resolution_order: Annotated[
            int | None, Field(ge=1, description="New resolution priority")
        ] = None,
        enabled: Annotated[bool | None, Field(description="Enable/disable repository")] = None,
        internal: Annotated[bool | None, Field(description="Mark as internal")] = None,
        username: Annotated[str | None, Field(description="New username")] = None,
        password: Annotated[str | None, Field(description="New password")] = None,
    ) -> dict:
        """
        Update an existing repository configuration.
        """
        try:
            client = get_client()
            payload = {"uuid": uuid}

            if identifier is not None:
                payload["identifier"] = identifier
            if url is not None:
                payload["url"] = url
            if resolution_order is not None:
                payload["resolutionOrder"] = resolution_order
            if enabled is not None:
                payload["enabled"] = enabled
            if internal is not None:
                payload["internal"] = internal
            if username is not None:
                payload["username"] = username
            if password is not None:
                payload["password"] = password

            data = await client.post("/repository", data=payload)
            return {"repository": data, "message": "Repository updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a repository",
        tags=[Scopes.WRITE_REPOSITORIES],
    )
    async def delete_repository(
        uuid: Annotated[str, Field(description="Repository UUID")],
    ) -> dict:
        """
        Delete a repository configuration.
        """
        try:
            client = get_client()
            await client.delete(f"/repository/{uuid}")
            return {"message": f"Repository {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Resolve the latest version of a component from repositories",
        tags=[Scopes.READ_REPOSITORIES],
    )
    async def resolve_latest_version(
        purl: Annotated[
            str, Field(description="Package URL to resolve (e.g., pkg:npm/lodash)")
        ],
    ) -> dict:
        """
        Attempt to resolve the latest version of a component from configured repositories.

        Returns version information if the component is found in any repository.
        """
        try:
            client = get_client()
            data = await client.get("/repository/latest", params={"purl": purl})
            return {"latestVersion": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
