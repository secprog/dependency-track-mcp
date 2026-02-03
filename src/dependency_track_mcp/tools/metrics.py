"""Metrics tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_metrics_tools(mcp: FastMCP) -> None:
    """Register metrics tools."""

    @mcp.tool(
        description="Get current security metrics for the entire portfolio",
        tags=[Scopes.READ_METRICS],
    )
    async def get_portfolio_metrics() -> dict:
        """
        Get current security metrics for the entire portfolio.

        Returns aggregate metrics including:
        - Vulnerability counts by severity (critical, high, medium, low)
        - Total components and vulnerable components
        - Policy violation counts
        - Inherited risk score
        """
        try:
            client = get_client()
            data = await client.get("/metrics/portfolio/current")
            return {"metrics": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get historical security metrics for the portfolio",
        tags=[Scopes.READ_METRICS],
    )
    async def get_portfolio_metrics_history(
        days: Annotated[
            int, Field(ge=1, le=365, description="Number of days of history")
        ] = 30,
    ) -> dict:
        """
        Get historical security metrics for the portfolio.

        Returns time-series data for tracking vulnerability trends
        and measuring remediation progress over time.
        """
        try:
            client = get_client()
            data = await client.get(
                "/metrics/portfolio/since",
                params={"days": days},
            )
            return {"metrics": data, "days": days}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get current security metrics for a specific project",
        tags=[Scopes.READ_METRICS],
    )
    async def get_project_metrics(
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Get current security metrics for a specific project.

        Returns project-specific metrics including:
        - Vulnerability counts by severity
        - Component counts
        - Policy violation counts
        - Inherited risk score
        """
        try:
            client = get_client()
            data = await client.get(f"/metrics/project/{project_uuid}/current")
            return {"metrics": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get historical security metrics for a project",
        tags=[Scopes.READ_METRICS],
    )
    async def get_project_metrics_history(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        days: Annotated[
            int, Field(ge=1, le=365, description="Number of days of history")
        ] = 30,
    ) -> dict:
        """
        Get historical security metrics for a specific project.

        Returns time-series data for tracking project vulnerability
        trends and remediation progress.
        """
        try:
            client = get_client()
            data = await client.get(
                f"/metrics/project/{project_uuid}/since",
                params={"days": days},
            )
            return {"metrics": data, "days": days}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Trigger a refresh of portfolio metrics",
        tags=[Scopes.READ_METRICS],
    )
    async def refresh_portfolio_metrics() -> dict:
        """
        Trigger a refresh of portfolio-wide security metrics.

        This recalculates all metrics across the portfolio.
        Note: This may take time for large portfolios.
        """
        try:
            client = get_client()
            await client.get("/metrics/portfolio/refresh")
            return {"message": "Portfolio metrics refresh initiated"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Trigger a refresh of project metrics",
        tags=[Scopes.READ_METRICS],
    )
    async def refresh_project_metrics(
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Trigger a refresh of metrics for a specific project.

        This recalculates vulnerability and component metrics for the project.
        """
        try:
            client = get_client()
            await client.get(f"/metrics/project/{project_uuid}/refresh")
            return {"message": f"Project {project_uuid} metrics refresh initiated"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get vulnerability metrics summary",
        tags=[Scopes.READ_METRICS],
    )
    async def get_vulnerability_metrics() -> dict:
        """
        Get vulnerability metrics summary.

        Returns statistics about vulnerabilities across the portfolio
        including counts by source and severity.
        """
        try:
            client = get_client()
            data = await client.get("/metrics/vulnerability")
            return {"metrics": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
