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
        description="List all vulnerabilities in the database",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def list_vulnerabilities(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all vulnerabilities in the database.

        Returns vulnerabilities with their metadata including severity,
        CVSS scores, and source information.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/vulnerability", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "vulnerabilities": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

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
        description="Get detailed information about a vulnerability by UUID",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def get_vulnerability_by_uuid(
        uuid: Annotated[str, Field(description="Vulnerability UUID")],
    ) -> dict:
        """
        Get detailed information about a vulnerability by its UUID.
        """
        try:
            client = get_client()
            data = await client.get(f"/vulnerability/{uuid}")
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

    @mcp.tool(
        description="List vulnerabilities affecting a specific project",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def list_project_vulnerabilities(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all vulnerabilities affecting components in a specific project.

        Returns vulnerability details including severity and CVSS scores.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/vulnerability/project/{project_uuid}", params=params
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

    @mcp.tool(
        description="Create a new internal vulnerability",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def create_vulnerability(
        vuln_id: Annotated[
            str, Field(description="Vulnerability ID (use generate_vuln_id for internal IDs)")
        ],
        title: Annotated[str, Field(description="Vulnerability title")],
        description: Annotated[str | None, Field(description="Detailed description")] = None,
        severity: Annotated[
            str | None,
            Field(description="Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO, UNASSIGNED"),
        ] = None,
        cvss_v3_vector: Annotated[
            str | None, Field(description="CVSS v3 vector string")
        ] = None,
        cwe_ids: Annotated[
            list[int] | None, Field(description="List of CWE IDs")
        ] = None,
        recommendation: Annotated[
            str | None, Field(description="Remediation recommendation")
        ] = None,
    ) -> dict:
        """
        Create a new internal vulnerability.

        Use generate_vuln_id to get the next available internal vulnerability ID.
        """
        try:
            client = get_client()
            payload = {
                "vulnId": vuln_id,
                "title": title,
                "source": "INTERNAL",
            }

            if description:
                payload["description"] = description
            if severity:
                payload["severity"] = severity
            if cvss_v3_vector:
                payload["cvssV3Vector"] = cvss_v3_vector
            if cwe_ids:
                payload["cwes"] = [{"cweId": cwe_id} for cwe_id in cwe_ids]
            if recommendation:
                payload["recommendation"] = recommendation

            data = await client.put("/vulnerability", data=payload)
            return {"vulnerability": data, "message": "Vulnerability created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing internal vulnerability",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def update_vulnerability(
        uuid: Annotated[str, Field(description="Vulnerability UUID")],
        title: Annotated[str | None, Field(description="New title")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        severity: Annotated[
            str | None,
            Field(description="New severity: CRITICAL, HIGH, MEDIUM, LOW, INFO, UNASSIGNED"),
        ] = None,
        cvss_v3_vector: Annotated[
            str | None, Field(description="New CVSS v3 vector string")
        ] = None,
        recommendation: Annotated[
            str | None, Field(description="New remediation recommendation")
        ] = None,
    ) -> dict:
        """
        Update an existing internal vulnerability.

        Only internal vulnerabilities can be updated.
        """
        try:
            client = get_client()

            # Get existing vulnerability
            existing = await client.get(f"/vulnerability/{uuid}")

            # Update fields
            if title is not None:
                existing["title"] = title
            if description is not None:
                existing["description"] = description
            if severity is not None:
                existing["severity"] = severity
            if cvss_v3_vector is not None:
                existing["cvssV3Vector"] = cvss_v3_vector
            if recommendation is not None:
                existing["recommendation"] = recommendation

            data = await client.post("/vulnerability", data=existing)
            return {"vulnerability": data, "message": "Vulnerability updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete an internal vulnerability",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def delete_vulnerability(
        uuid: Annotated[str, Field(description="Vulnerability UUID")],
    ) -> dict:
        """
        Delete an internal vulnerability.

        Only internal vulnerabilities can be deleted.
        """
        try:
            client = get_client()
            await client.delete(f"/vulnerability/{uuid}")
            return {"message": f"Vulnerability {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Generate a new internal vulnerability ID",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def generate_vuln_id() -> dict:
        """
        Generate a new internal vulnerability identifier.

        Returns the next available ID in the format INT-XXXX.
        Use this before creating a new internal vulnerability.
        """
        try:
            client = get_client()
            data = await client.get("/vulnerability/vulnId")
            return {"vuln_id": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Assign a vulnerability to a component by source and vuln ID",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def assign_vulnerability_to_component(
        source: Annotated[
            str,
            Field(description="Vulnerability source (NVD, INTERNAL, etc.)"),
        ],
        vuln_id: Annotated[str, Field(description="Vulnerability ID")],
        component_uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        Assign a vulnerability to a component.

        Creates an association between the vulnerability and component,
        indicating the component is affected.
        """
        try:
            client = get_client()
            await client.post(
                f"/vulnerability/source/{source}/vuln/{vuln_id}/component/{component_uuid}"
            )
            return {"message": "Vulnerability assigned to component successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a vulnerability assignment from a component by source and vuln ID",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def unassign_vulnerability_from_component(
        source: Annotated[
            str,
            Field(description="Vulnerability source (NVD, INTERNAL, etc.)"),
        ],
        vuln_id: Annotated[str, Field(description="Vulnerability ID")],
        component_uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        Remove a vulnerability assignment from a component.

        Removes the association between the vulnerability and component.
        """
        try:
            client = get_client()
            await client.delete(
                f"/vulnerability/source/{source}/vuln/{vuln_id}/component/{component_uuid}"
            )
            return {"message": "Vulnerability unassigned from component successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Assign a vulnerability to a component by UUID",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def assign_vulnerability_by_uuid(
        vulnerability_uuid: Annotated[str, Field(description="Vulnerability UUID")],
        component_uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        Assign a vulnerability to a component using UUIDs.

        Alternative to assign_vulnerability_to_component when you have the UUID.
        """
        try:
            client = get_client()
            await client.post(
                f"/vulnerability/{vulnerability_uuid}/component/{component_uuid}"
            )
            return {"message": "Vulnerability assigned to component successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a vulnerability assignment from a component by UUID",
        tags=[Scopes.WRITE_VULNERABILITIES],
    )
    async def unassign_vulnerability_by_uuid(
        vulnerability_uuid: Annotated[str, Field(description="Vulnerability UUID")],
        component_uuid: Annotated[str, Field(description="Component UUID")],
    ) -> dict:
        """
        Remove a vulnerability assignment from a component using UUIDs.

        Alternative to unassign_vulnerability_from_component when you have the UUID.
        """
        try:
            client = get_client()
            await client.delete(
                f"/vulnerability/{vulnerability_uuid}/component/{component_uuid}"
            )
            return {"message": "Vulnerability unassigned from component successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
