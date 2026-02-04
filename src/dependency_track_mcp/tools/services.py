"""Service component tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_service_tools(mcp: FastMCP) -> None:
    """Register service component tools."""

    @mcp.tool(
        description="List all services in a project",
        tags=[Scopes.READ_SERVICES],
    )
    async def list_project_services(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List all services in a project.

        Services represent external services/APIs that a project depends on.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/service/project/{project_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "services": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get a specific service by UUID",
        tags=[Scopes.READ_SERVICES],
    )
    async def get_service(
        uuid: Annotated[str, Field(description="Service UUID")],
    ) -> dict:
        """
        Get detailed information about a specific service.
        """
        try:
            client = get_client()
            data = await client.get(f"/service/{uuid}")
            return {"service": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new service in a project",
        tags=[Scopes.WRITE_SERVICES],
    )
    async def create_service(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        name: Annotated[str, Field(description="Service name")],
        version: Annotated[str | None, Field(description="Service version")] = None,
        group: Annotated[str | None, Field(description="Service group/namespace")] = None,
        description: Annotated[str | None, Field(description="Service description")] = None,
        endpoints: Annotated[list[str] | None, Field(description="List of endpoint URLs")] = None,
        authenticated: Annotated[
            bool | None, Field(description="Whether authentication is required")
        ] = None,
        x_trust_boundary: Annotated[
            bool | None, Field(description="Whether service crosses trust boundary")
        ] = None,
        provider_name: Annotated[str | None, Field(description="Service provider name")] = None,
        provider_url: Annotated[str | None, Field(description="Service provider URL")] = None,
    ) -> dict:
        """
        Create a new service in a project.

        Services represent external dependencies like APIs, databases,
        and cloud services.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "project": {"uuid": project_uuid},
            }

            if version:
                payload["version"] = version
            if group:
                payload["group"] = group
            if description:
                payload["description"] = description
            if endpoints:
                payload["endpoints"] = endpoints
            if authenticated is not None:
                payload["authenticated"] = authenticated
            if x_trust_boundary is not None:
                payload["xTrustBoundary"] = x_trust_boundary
            if provider_name or provider_url:
                payload["provider"] = {}
                if provider_name:
                    payload["provider"]["name"] = provider_name
                if provider_url:
                    payload["provider"]["url"] = provider_url

            data = await client.put(f"/service/project/{project_uuid}", data=payload)
            return {"service": data, "message": "Service created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing service",
        tags=[Scopes.WRITE_SERVICES],
    )
    async def update_service(
        uuid: Annotated[str, Field(description="Service UUID")],
        name: Annotated[str | None, Field(description="New service name")] = None,
        version: Annotated[str | None, Field(description="New service version")] = None,
        group: Annotated[str | None, Field(description="New service group")] = None,
        description: Annotated[str | None, Field(description="New description")] = None,
        endpoints: Annotated[
            list[str] | None, Field(description="New list of endpoint URLs")
        ] = None,
        authenticated: Annotated[
            bool | None, Field(description="Whether authentication is required")
        ] = None,
        x_trust_boundary: Annotated[
            bool | None, Field(description="Whether service crosses trust boundary")
        ] = None,
    ) -> dict:
        """
        Update an existing service's properties.
        """
        try:
            client = get_client()

            # Get existing service
            existing = await client.get(f"/service/{uuid}")

            # Update fields
            if name is not None:
                existing["name"] = name
            if version is not None:
                existing["version"] = version
            if group is not None:
                existing["group"] = group
            if description is not None:
                existing["description"] = description
            if endpoints is not None:
                existing["endpoints"] = endpoints
            if authenticated is not None:
                existing["authenticated"] = authenticated
            if x_trust_boundary is not None:
                existing["xTrustBoundary"] = x_trust_boundary

            data = await client.post("/service", data=existing)
            return {"service": data, "message": "Service updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a service",
        tags=[Scopes.WRITE_SERVICES],
    )
    async def delete_service(
        uuid: Annotated[str, Field(description="Service UUID")],
    ) -> dict:
        """
        Delete a service from a project.
        """
        try:
            client = get_client()
            await client.delete(f"/service/{uuid}")
            return {"message": f"Service {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
