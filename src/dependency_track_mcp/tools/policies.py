"""Policy violation tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_policy_tools(mcp: FastMCP) -> None:
    """Register policy violation tools."""

    @mcp.tool(
        description="List all policy violations across the portfolio",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_policy_violations(
        suppressed: Annotated[
            bool, Field(description="Include suppressed violations")
        ] = False,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all policy violations across the portfolio.

        Returns violations categorized by type:
        - LICENSE: License compatibility violations
        - SECURITY: Security policy violations (e.g., CVSS thresholds)
        - OPERATIONAL: Operational policy violations
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
                "suppressed": str(suppressed).lower(),
            }
            data, headers = await client.get_with_headers(
                "/violation", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "violations": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List policy violations for a specific project",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_project_policy_violations(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        suppressed: Annotated[
            bool, Field(description="Include suppressed violations")
        ] = False,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List policy violations for a specific project.

        Returns all policy violations affecting components in the project,
        including violation type, severity, and the triggering policy condition.
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
                "suppressed": str(suppressed).lower(),
            }
            data, headers = await client.get_with_headers(
                f"/violation/project/{project_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "violations": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List policy violations for a specific component",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_component_policy_violations(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        suppressed: Annotated[
            bool, Field(description="Include suppressed violations")
        ] = False,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List policy violations for a specific component.

        Returns all policy violations triggered by this component
        including license, security, and operational violations.
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
                "suppressed": str(suppressed).lower(),
            }
            data, headers = await client.get_with_headers(
                f"/violation/component/{component_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "violations": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List all security policies",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_policies(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all security policies defined in Dependency Track.

        Policies define rules that trigger violations based on:
        - License conditions (forbidden/allowed licenses)
        - Security conditions (CVSS thresholds, specific CVEs)
        - Operational conditions (component age, coordinates)
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/policy", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "policies": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
