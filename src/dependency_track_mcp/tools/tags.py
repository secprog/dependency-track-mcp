"""Tag management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_tag_tools(mcp: FastMCP) -> None:
    """Register tag management tools."""

    @mcp.tool(
        description="List all tags",
        tags=[Scopes.READ_TAGS],
    )
    async def list_tags(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all tags defined in Dependency Track.

        Tags can be used to organize projects and apply policies.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/tag", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "tags": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create one or more tags",
        tags=[Scopes.WRITE_TAGS],
    )
    async def create_tags(
        names: Annotated[list[str], Field(description="List of tag names to create")],
    ) -> dict:
        """
        Create one or more tags.

        Tags that already exist will be skipped.
        """
        try:
            client = get_client()
            payload = [{"name": name} for name in names]
            data = await client.put("/tag", data=payload)
            return {"tags": data, "message": f"Created {len(names)} tag(s) successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete one or more tags",
        tags=[Scopes.WRITE_TAGS],
    )
    async def delete_tags(
        names: Annotated[list[str], Field(description="List of tag names to delete")],
    ) -> dict:
        """
        Delete one or more tags.

        This removes the tags from all associated projects and policies.
        """
        try:
            client = get_client()
            tag_data = [{"name": name} for name in names]
            await client.delete("/tag", data=tag_data)
            return {"message": f"Deleted {len(names)} tag(s) successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get all projects assigned to a tag",
        tags=[Scopes.READ_TAGS],
    )
    async def get_tag_projects(
        tag_name: Annotated[str, Field(description="Tag name")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get all projects that have the specified tag.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/tag/{tag_name}/project", params=params
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
        description="Tag one or more projects",
        tags=[Scopes.WRITE_TAGS],
    )
    async def tag_projects(
        tag_name: Annotated[str, Field(description="Tag name")],
        project_uuids: Annotated[list[str], Field(description="List of project UUIDs to tag")],
    ) -> dict:
        """
        Apply a tag to one or more projects.
        """
        try:
            client = get_client()
            await client.post(f"/tag/{tag_name}/project", data=project_uuids)
            return {"message": f"Tagged {len(project_uuids)} project(s) successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Untag one or more projects",
        tags=[Scopes.WRITE_TAGS],
    )
    async def untag_projects(
        tag_name: Annotated[str, Field(description="Tag name")],
        project_uuids: Annotated[list[str], Field(description="List of project UUIDs to untag")],
    ) -> dict:
        """
        Remove a tag from one or more projects.
        """
        try:
            client = get_client()
            await client.delete(
                f"/tag/{tag_name}/project",
                params={"uuids": ",".join(project_uuids)},
            )
            return {"message": f"Untagged {len(project_uuids)} project(s) successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get all policies assigned to a tag",
        tags=[Scopes.READ_TAGS],
    )
    async def get_tag_policies(
        tag_name: Annotated[str, Field(description="Tag name")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get all policies that have the specified tag.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/tag/{tag_name}/policy", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "policies": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Tag one or more policies",
        tags=[Scopes.WRITE_TAGS],
    )
    async def tag_policies(
        tag_name: Annotated[str, Field(description="Tag name")],
        policy_uuids: Annotated[list[str], Field(description="List of policy UUIDs to tag")],
    ) -> dict:
        """
        Apply a tag to one or more policies.
        """
        try:
            client = get_client()
            await client.post(f"/tag/{tag_name}/policy", data=policy_uuids)
            return {"message": f"Tagged {len(policy_uuids)} policy(ies) successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Untag one or more policies",
        tags=[Scopes.WRITE_TAGS],
    )
    async def untag_policies(
        tag_name: Annotated[str, Field(description="Tag name")],
        policy_uuids: Annotated[list[str], Field(description="List of policy UUIDs to untag")],
    ) -> dict:
        """
        Remove a tag from one or more policies.
        """
        try:
            client = get_client()
            await client.delete(f"/tag/{tag_name}/policy", params={"uuids": ",".join(policy_uuids)})
            return {"message": f"Untagged {len(policy_uuids)} policy(ies) successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get all notification rules assigned to a tag",
        tags=[Scopes.READ_TAGS],
    )
    async def get_tag_notification_rules(
        tag_name: Annotated[str, Field(description="Tag name")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get all notification rules that have the specified tag.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/tag/{tag_name}/notificationRule", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "notificationRules": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get tags associated with a policy",
        tags=[Scopes.READ_TAGS],
    )
    async def get_policy_tags(
        policy_uuid: Annotated[str, Field(description="Policy UUID")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get all tags associated with a specific policy.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/tag/policy/{policy_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "tags": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get collection projects that use a tag for their collection logic",
        tags=[Scopes.READ_TAGS],
    )
    async def get_tag_collection_projects(
        tag_name: Annotated[str, Field(description="Tag name")],
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        Get all collection projects that use the specified tag for their collection logic.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                f"/tag/{tag_name}/collectionProject", params=params
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
