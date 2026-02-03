"""CWE (Common Weakness Enumeration) tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_cwe_tools(mcp: FastMCP) -> None:
    """Register CWE lookup tools."""

    @mcp.tool(
        description="List all CWEs (Common Weakness Enumeration)",
        tags=[Scopes.READ_CWE],
    )
    async def list_cwes(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all CWEs in the database.

        CWEs describe common software weaknesses and are used to
        categorize vulnerabilities.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/cwe", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "cwes": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get a specific CWE by its ID",
        tags=[Scopes.READ_CWE],
    )
    async def get_cwe(
        cwe_id: Annotated[int, Field(description="CWE ID (e.g., 79 for XSS)")],
    ) -> dict:
        """
        Get detailed information about a specific CWE.

        Returns the CWE name, description, and related information.
        """
        try:
            client = get_client()
            data = await client.get(f"/cwe/{cwe_id}")
            return {"cwe": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
