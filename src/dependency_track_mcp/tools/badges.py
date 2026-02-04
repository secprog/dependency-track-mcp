"""Badge generation tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_badge_tools(mcp: FastMCP) -> None:
    """Register badge generation tools."""

    @mcp.tool(
        description="Get vulnerability badge for a project by UUID",
        tags=[Scopes.SYSTEM_BADGES],
    )
    async def get_vulnerability_badge_by_uuid(
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Get an SVG badge showing vulnerability metrics for a project.

        The badge displays the number of vulnerabilities by severity.
        Can be embedded in README files or dashboards.
        """
        try:
            client = get_client()
            data = await client.get(f"/badge/vulns/project/{project_uuid}")
            return {"badge": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get vulnerability badge for a project by name and version",
        tags=[Scopes.SYSTEM_BADGES],
    )
    async def get_vulnerability_badge_by_name(
        project_name: Annotated[str, Field(description="Project name")],
        project_version: Annotated[str, Field(description="Project version")],
    ) -> dict:
        """
        Get an SVG badge showing vulnerability metrics for a project.

        The badge displays the number of vulnerabilities by severity.
        """
        try:
            client = get_client()
            data = await client.get(f"/badge/vulns/project/{project_name}/{project_version}")
            return {"badge": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get policy violations badge for a project by UUID",
        tags=[Scopes.SYSTEM_BADGES],
    )
    async def get_violations_badge_by_uuid(
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Get an SVG badge showing policy violation metrics for a project.

        The badge displays the number of policy violations by severity.
        """
        try:
            client = get_client()
            data = await client.get(f"/badge/violations/project/{project_uuid}")
            return {"badge": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get policy violations badge for a project by name and version",
        tags=[Scopes.SYSTEM_BADGES],
    )
    async def get_violations_badge_by_name(
        project_name: Annotated[str, Field(description="Project name")],
        project_version: Annotated[str, Field(description="Project version")],
    ) -> dict:
        """
        Get an SVG badge showing policy violation metrics for a project.

        The badge displays the number of policy violations by severity.
        """
        try:
            client = get_client()
            data = await client.get(f"/badge/violations/project/{project_name}/{project_version}")
            return {"badge": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
