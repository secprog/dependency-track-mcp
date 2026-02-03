"""Search tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_search_tools(mcp: FastMCP) -> None:
    """Register search tools."""

    @mcp.tool(
        description="Search across all entity types in Dependency Track",
        tags=[Scopes.SEARCH],
    )
    async def search(
        query: Annotated[str, Field(description="Search query string")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Search across all entity types in Dependency Track.

        Returns matching projects, components, vulnerabilities, and licenses.
        Uses full-text search on names, descriptions, and identifiers.
        """
        try:
            client = get_client()
            params = {
                "query": query,
                "pageNumber": page,
                "pageSize": page_size,
            }
            data = await client.get("/search", params=params)
            return {"results": data, "query": query}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Search for projects by name",
        tags=[Scopes.SEARCH],
    )
    async def search_projects(
        query: Annotated[str, Field(description="Project name search query")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Search for projects by name.

        Finds projects whose name contains the search query.
        """
        try:
            client = get_client()
            params = {
                "query": query,
                "pageNumber": page,
                "pageSize": page_size,
            }
            data, headers = await client.get_with_headers(
                "/search/project", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "projects": data,
                "total": int(total_count),
                "query": query,
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Search for components by name, group, or PURL",
        tags=[Scopes.SEARCH],
    )
    async def search_components(
        query: Annotated[
            str, Field(description="Component name, group, or PURL search query")
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Search for components by name, group, or Package URL.

        Finds components matching the search query across all projects.
        Useful for finding all instances of a specific library.
        """
        try:
            client = get_client()
            params = {
                "query": query,
                "pageNumber": page,
                "pageSize": page_size,
            }
            data, headers = await client.get_with_headers(
                "/search/component", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "components": data,
                "total": int(total_count),
                "query": query,
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Search for vulnerabilities by CVE ID or description",
        tags=[Scopes.SEARCH],
    )
    async def search_vulnerabilities(
        query: Annotated[
            str, Field(description="CVE ID or vulnerability description search query")
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Search for vulnerabilities by CVE ID or description.

        Finds vulnerabilities matching the search query.
        Supports searching by CVE ID (e.g., CVE-2021-44228) or keywords.
        """
        try:
            client = get_client()
            params = {
                "query": query,
                "pageNumber": page,
                "pageSize": page_size,
            }
            data, headers = await client.get_with_headers(
                "/search/vulnerability", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "vulnerabilities": data,
                "total": int(total_count),
                "query": query,
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Search for licenses by name or SPDX ID",
        tags=[Scopes.SEARCH],
    )
    async def search_licenses(
        query: Annotated[
            str, Field(description="License name or SPDX ID search query")
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Search for licenses by name or SPDX identifier.

        Finds licenses matching the search query.
        Supports SPDX identifiers (e.g., MIT, Apache-2.0) and full names.
        """
        try:
            client = get_client()
            params = {
                "query": query,
                "pageNumber": page,
                "pageSize": page_size,
            }
            data, headers = await client.get_with_headers(
                "/search/license", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "licenses": data,
                "total": int(total_count),
                "query": query,
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Search for services by name",
        tags=[Scopes.SEARCH],
    )
    async def search_services(
        query: Annotated[str, Field(description="Service name search query")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Search for services by name.

        Finds services matching the search query across all projects.
        """
        try:
            client = get_client()
            params = {
                "query": query,
                "pageNumber": page,
                "pageSize": page_size,
            }
            data, headers = await client.get_with_headers(
                "/search/service", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "services": data,
                "total": int(total_count),
                "query": query,
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Search for vulnerable software by CPE or keyword",
        tags=[Scopes.SEARCH],
    )
    async def search_vulnerable_software(
        query: Annotated[
            str, Field(description="CPE or software name search query")
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Search for vulnerable software by CPE identifier or name.

        Finds vulnerable software entries in the NVD database
        that match the search query.
        """
        try:
            client = get_client()
            params = {
                "query": query,
                "pageNumber": page,
                "pageSize": page_size,
            }
            data, headers = await client.get_with_headers(
                "/search/vulnerablesoftware", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "vulnerableSoftware": data,
                "total": int(total_count),
                "query": query,
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Trigger reindexing of the search indexes",
        tags=[Scopes.SEARCH],
    )
    async def reindex_search() -> dict:
        """
        Trigger a rebuild of Lucene search indexes.

        This is an administrative operation that rebuilds all search
        indexes. Use when search results appear to be stale or incomplete.
        """
        try:
            client = get_client()
            await client.post("/search/reindex")
            return {"message": "Search reindex initiated"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
