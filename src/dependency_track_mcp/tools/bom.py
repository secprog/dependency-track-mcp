"""BOM (Software Bill of Materials) tools for Dependency Track."""

import base64
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_bom_tools(mcp: FastMCP) -> None:
    """Register BOM tools."""

    @mcp.tool(
        description="Upload a Software Bill of Materials (SBOM) to a project",
        tags=[Scopes.UPLOAD_BOM],
    )
    async def upload_bom(
        project_uuid: Annotated[
            str | None, Field(description="Target project UUID (required if not auto-creating)")
        ] = None,
        project_name: Annotated[
            str | None, Field(description="Project name (for auto-create)")
        ] = None,
        project_version: Annotated[
            str | None, Field(description="Project version (for auto-create)")
        ] = None,
        bom: Annotated[
            str, Field(description="SBOM content (CycloneDX or SPDX in JSON/XML format)")
        ] = "",
        auto_create: Annotated[
            bool, Field(description="Auto-create project if it doesn't exist")
        ] = False,
    ) -> dict:
        """
        Upload a Software Bill of Materials (SBOM) to Dependency Track.

        Supports CycloneDX and SPDX formats in both JSON and XML.
        The BOM content should be provided as a string (raw JSON/XML).

        Either provide project_uuid for an existing project, or use
        auto_create=True with project_name and project_version to
        create a new project automatically.
        """
        try:
            if not project_uuid and not (auto_create and project_name):
                return {
                    "error": "Either project_uuid or (auto_create with project_name) is required"
                }

            if not bom:
                return {"error": "BOM content is required"}

            client = get_client()

            # Base64 encode the BOM
            bom_encoded = base64.b64encode(bom.encode("utf-8")).decode("utf-8")

            payload = {"bom": bom_encoded}

            if project_uuid:
                payload["project"] = project_uuid
            if auto_create:
                payload["autoCreate"] = True
            if project_name:
                payload["projectName"] = project_name
            if project_version:
                payload["projectVersion"] = project_version

            data = await client.put("/bom", data=payload)

            return {
                "token": data.get("token"),
                "message": "BOM uploaded successfully. Use check_bom_processing to monitor status.",
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Check the processing status of an uploaded BOM",
        tags=[Scopes.UPLOAD_BOM],
    )
    async def check_bom_processing(
        token: Annotated[str, Field(description="BOM upload token")],
    ) -> dict:
        """
        Check the processing status of an uploaded BOM.

        Returns whether the BOM is still being processed or has completed.
        Use the token returned from upload_bom.
        """
        try:
            client = get_client()
            data = await client.get(f"/bom/token/{token}")
            return {
                "processing": data.get("processing", False),
                "message": "BOM is still processing" if data.get("processing") else "BOM processing complete",
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Export a project's BOM in CycloneDX format",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def export_project_bom(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        format: Annotated[
            str, Field(description="Export format: json or xml")
        ] = "json",
        variant: Annotated[
            str,
            Field(
                description="BOM variant: inventory (components only), withVulnerabilities (components + vulns), or vex (VEX format)"
            ),
        ] = "inventory",
    ) -> dict:
        """
        Export a project's Software Bill of Materials.

        Variants:
        - inventory: Components only
        - withVulnerabilities: Components with vulnerability data
        - vex: Vulnerability Exploitability eXchange (VEX) format
        """
        try:
            client = get_client()

            # Map variant to download type
            download_map = {
                "inventory": "inventory",
                "withVulnerabilities": "inventoryWithVulnerabilities",
                "vex": "vex",
            }
            download_type = download_map.get(variant, "inventory")

            params = {
                "format": format,
                "variant": download_type,
            }

            data = await client.get(f"/bom/cyclonedx/project/{project_uuid}", params=params)
            return {"bom": data, "format": format, "variant": variant}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Export a component's BOM in CycloneDX format",
        tags=[Scopes.READ_COMPONENTS],
    )
    async def export_component_bom(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        format: Annotated[
            str, Field(description="Export format: json or xml")
        ] = "json",
    ) -> dict:
        """
        Export a component's information in CycloneDX BOM format.

        Returns the component with its metadata, license information,
        and hashes in CycloneDX format.
        """
        try:
            client = get_client()
            params = {"format": format}
            data = await client.get(
                f"/bom/cyclonedx/component/{component_uuid}", params=params
            )
            return {"bom": data, "format": format}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Validate a BOM without uploading it",
        tags=[Scopes.UPLOAD_BOM],
    )
    async def validate_bom(
        bom: Annotated[
            str, Field(description="SBOM content (CycloneDX or SPDX in JSON/XML format)")
        ],
    ) -> dict:
        """
        Validate a Software Bill of Materials without uploading.

        Checks if the BOM is valid and can be processed by Dependency Track.
        Useful for CI/CD validation before actual upload.
        """
        try:
            client = get_client()
            bom_encoded = base64.b64encode(bom.encode("utf-8")).decode("utf-8")
            data = await client.post("/bom/validate", data={"bom": bom_encoded})
            return {
                "valid": data.get("valid", True),
                "validationErrors": data.get("validationErrors", []),
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
