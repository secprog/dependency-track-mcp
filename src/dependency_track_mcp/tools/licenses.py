"""License management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_license_tools(mcp: FastMCP) -> None:
    """Register license management tools."""

    @mcp.tool(
        description="List all licenses with complete metadata",
        tags=[Scopes.READ_LICENSES],
    )
    async def list_licenses(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all licenses with complete metadata.

        Returns licenses with full details including SPDX ID, OSI approval status,
        and license text.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/license", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "licenses": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List all licenses in concise format",
        tags=[Scopes.READ_LICENSES],
    )
    async def list_licenses_concise(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all licenses in a concise format.

        Returns a lightweight list with just essential license information,
        suitable for dropdowns and selection lists.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/license/concise", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "licenses": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get a specific license by its ID",
        tags=[Scopes.READ_LICENSES],
    )
    async def get_license(
        license_id: Annotated[str, Field(description="License ID (SPDX ID or UUID)")],
    ) -> dict:
        """
        Get detailed information about a specific license.

        Returns full license metadata including text, comments, and see-also URLs.
        """
        try:
            client = get_client()
            data = await client.get(f"/license/{license_id}")
            return {"license": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a custom license",
        tags=[Scopes.WRITE_LICENSES],
    )
    async def create_license(
        name: Annotated[str, Field(description="License name")],
        license_id: Annotated[str | None, Field(description="Custom license ID")] = None,
        license_text: Annotated[str | None, Field(description="Full license text")] = None,
        header: Annotated[str | None, Field(description="License header text")] = None,
        template: Annotated[str | None, Field(description="License template")] = None,
        comment: Annotated[str | None, Field(description="License comment")] = None,
        see_also: Annotated[list[str] | None, Field(description="Related URLs")] = None,
        is_osi_approved: Annotated[
            bool, Field(description="OSI approved status")
        ] = False,
        is_fsf_libre: Annotated[
            bool, Field(description="FSF libre status")
        ] = False,
        is_deprecated_license_id: Annotated[
            bool, Field(description="Deprecated license ID status")
        ] = False,
    ) -> dict:
        """
        Create a new custom license.

        Use this for licenses not in the SPDX database.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "isOsiApproved": is_osi_approved,
                "isFsfLibre": is_fsf_libre,
                "isDeprecatedLicenseId": is_deprecated_license_id,
            }

            if license_id:
                payload["licenseId"] = license_id
            if license_text:
                payload["licenseText"] = license_text
            if header:
                payload["header"] = header
            if template:
                payload["template"] = template
            if comment:
                payload["comment"] = comment
            if see_also:
                payload["seeAlso"] = see_also

            data = await client.put("/license", data=payload)
            return {"license": data, "message": "License created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a custom license",
        tags=[Scopes.WRITE_LICENSES],
    )
    async def delete_license(
        license_id: Annotated[str, Field(description="License ID to delete")],
    ) -> dict:
        """
        Delete a custom license.

        Only custom licenses can be deleted; SPDX licenses cannot be removed.
        """
        try:
            client = get_client()
            await client.delete(f"/license/{license_id}")
            return {"message": f"License {license_id} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
