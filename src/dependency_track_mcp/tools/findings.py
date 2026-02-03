"""Finding and analysis tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.models import AnalysisJustification, AnalysisResponse, AnalysisState
from dependency_track_mcp.scopes import Scopes


def register_finding_tools(mcp: FastMCP) -> None:
    """Register finding and analysis tools."""

    @mcp.tool(
        description="List all security findings for a project",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def list_project_findings(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        suppressed: Annotated[
            bool, Field(description="Include suppressed findings")
        ] = False,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all security findings for a project.

        A finding is the combination of a component and a vulnerability.
        Returns findings with component details, vulnerability info,
        and analysis status.
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
                "suppressed": str(suppressed).lower(),
            }
            data, headers = await client.get_with_headers(
                f"/finding/project/{project_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "findings": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get the analysis decision for a specific finding",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def get_finding_analysis(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        vulnerability_uuid: Annotated[str, Field(description="Vulnerability UUID")],
    ) -> dict:
        """
        Get the analysis decision for a specific finding.

        Returns the current analysis state, justification, response,
        and any comments recorded during triage.
        """
        try:
            client = get_client()
            data = await client.get(
                f"/analysis",
                params={
                    "component": component_uuid,
                    "vulnerability": vulnerability_uuid,
                },
            )
            return {"analysis": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Record an analysis decision for a finding (triage)",
        tags=[Scopes.WRITE_ANALYSIS],
    )
    async def update_finding_analysis(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        component_uuid: Annotated[str, Field(description="Component UUID")],
        vulnerability_uuid: Annotated[str, Field(description="Vulnerability UUID")],
        state: Annotated[
            str | None,
            Field(
                description="Analysis state: NOT_SET, EXPLOITABLE, IN_TRIAGE, RESOLVED, FALSE_POSITIVE, NOT_AFFECTED"
            ),
        ] = None,
        justification: Annotated[
            str | None,
            Field(
                description="Justification: CODE_NOT_PRESENT, CODE_NOT_REACHABLE, REQUIRES_CONFIGURATION, REQUIRES_DEPENDENCY, REQUIRES_ENVIRONMENT, PROTECTED_BY_COMPILER, PROTECTED_AT_RUNTIME, PROTECTED_AT_PERIMETER, PROTECTED_BY_MITIGATING_CONTROL"
            ),
        ] = None,
        response: Annotated[
            str | None,
            Field(
                description="Response: CAN_NOT_FIX, WILL_NOT_FIX, UPDATE, ROLLBACK, WORKAROUND_AVAILABLE"
            ),
        ] = None,
        details: Annotated[
            str | None, Field(description="Additional analysis details")
        ] = None,
        comment: Annotated[
            str | None, Field(description="Comment to add to the analysis trail")
        ] = None,
        suppressed: Annotated[
            bool | None, Field(description="Suppress this finding")
        ] = None,
    ) -> dict:
        """
        Record an analysis decision for a security finding.

        This is used for vulnerability triage to document whether a
        finding is exploitable, a false positive, or not affected,
        along with justification and remediation response.
        """
        try:
            client = get_client()
            payload = {
                "project": project_uuid,
                "component": component_uuid,
                "vulnerability": vulnerability_uuid,
            }

            if state:
                # Validate state
                try:
                    AnalysisState(state)
                except ValueError:
                    return {
                        "error": f"Invalid state: {state}",
                        "valid_states": [s.value for s in AnalysisState],
                    }
                payload["analysisState"] = state

            if justification:
                try:
                    AnalysisJustification(justification)
                except ValueError:
                    return {
                        "error": f"Invalid justification: {justification}",
                        "valid_justifications": [j.value for j in AnalysisJustification],
                    }
                payload["analysisJustification"] = justification

            if response:
                try:
                    AnalysisResponse(response)
                except ValueError:
                    return {
                        "error": f"Invalid response: {response}",
                        "valid_responses": [r.value for r in AnalysisResponse],
                    }
                payload["analysisResponse"] = response

            if details:
                payload["analysisDetails"] = details
            if comment:
                payload["comment"] = comment
            if suppressed is not None:
                payload["isSuppressed"] = suppressed

            data = await client.put("/analysis", data=payload)
            return {
                "analysis": data,
                "message": "Analysis decision recorded successfully",
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get findings summary grouped by vulnerability",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def list_findings_grouped(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get findings grouped by vulnerability across all projects.

        Useful for understanding which vulnerabilities are most
        prevalent across your portfolio.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/finding", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "findings": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
