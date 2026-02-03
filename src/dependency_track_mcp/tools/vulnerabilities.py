"""Vulnerability tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_vulnerability_tools(mcp: FastMCP) -> None:
    """Register vulnerability tools."""

    @mcp.tool(
        description="Get detailed information about a vulnerability by its ID",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def get_vulnerability(
        source: Annotated[
            str,
            Field(
                description="Vulnerability source (NVD, GITHUB, OSV, OSSINDEX, VULNDB, SNYK)"
            ),
        ],
        vuln_id: Annotated[
            str, Field(description="Vulnerability ID (e.g., CVE-2021-44228)")
        ],
    ) -> dict:
        """
        Get detailed information about a specific vulnerability.

        Returns vulnerability details including severity, CVSS scores,
        description, CWEs, and recommendations.
        """
        try:
            client = get_client()
            data = await client.get(f"/vulnerability/source/{source}/vuln/{vuln_id}")
            return {"vulnerability": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get all projects affected by a specific vulnerability",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def get_affected_projects(
        source: Annotated[
            str,
            Field(
                description="Vulnerability source (NVD, GITHUB, OSV, OSSINDEX, VULNDB, SNYK)"
            ),
        ],
        vuln_id: Annotated[
            str, Field(description="Vulnerability ID (e.g., CVE-2021-44228)")
        ],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get all projects affected by a specific vulnerability.

        Useful for understanding the portfolio-wide impact of a CVE
        and prioritizing remediation efforts.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/vulnerability/source/{source}/vuln/{vuln_id}/projects",
                params=params,
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
        description="List vulnerabilities affecting a specific component",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def list_component_vulnerabilities(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all vulnerabilities affecting a specific component.

        Returns vulnerability details including severity and CVSS scores.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/vulnerability/component/{component_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "vulnerabilities": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
