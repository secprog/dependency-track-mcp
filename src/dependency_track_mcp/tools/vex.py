"""VEX (Vulnerability Exploitability eXchange) tools for Dependency Track."""

import base64
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_vex_tools(mcp: FastMCP) -> None:
    """Register VEX tools."""

    @mcp.tool(
        description="Upload a VEX document using PUT method",
        tags=[Scopes.UPLOAD_VEX],
    )
    async def upload_vex(
        project_uuid: Annotated[str, Field(description="Target project UUID")],
        vex: Annotated[
            str, Field(description="VEX document content (CycloneDX VEX format)")
        ],
    ) -> dict:
        """
        Upload a VEX (Vulnerability Exploitability eXchange) document.

        VEX documents communicate the exploitability status of vulnerabilities
        in a product. They can update the analysis status of findings.
        """
        try:
            client = get_client()

            # Base64 encode the VEX
            vex_encoded = base64.b64encode(vex.encode("utf-8")).decode("utf-8")

            payload = {
                "project": project_uuid,
                "vex": vex_encoded,
            }

            data = await client.put("/vex", data=payload)
            return {
                "token": data.get("token") if data else None,
                "message": "VEX document uploaded successfully",
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Upload a VEX document using POST method",
        tags=[Scopes.UPLOAD_VEX],
    )
    async def upload_vex_post(
        project_uuid: Annotated[str, Field(description="Target project UUID")],
        vex: Annotated[
            str, Field(description="VEX document content (CycloneDX VEX format)")
        ],
    ) -> dict:
        """
        Upload a VEX document using POST method.

        Alternative to upload_vex (PUT). Both methods achieve the same result.
        """
        try:
            client = get_client()

            # Base64 encode the VEX
            vex_encoded = base64.b64encode(vex.encode("utf-8")).decode("utf-8")

            payload = {
                "project": project_uuid,
                "vex": vex_encoded,
            }

            data = await client.post("/vex", data=payload)
            return {
                "token": data.get("token") if data else None,
                "message": "VEX document uploaded successfully",
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Export a project's VEX in CycloneDX format",
        tags=[Scopes.READ_VULNERABILITIES],
    )
    async def export_project_vex(
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Export a project's VEX (Vulnerability Exploitability eXchange) document.

        Returns a CycloneDX VEX document containing the vulnerability
        analysis status for all findings in the project.
        """
        try:
            client = get_client()
            data = await client.get(f"/vex/cyclonedx/project/{project_uuid}")
            return {"vex": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
