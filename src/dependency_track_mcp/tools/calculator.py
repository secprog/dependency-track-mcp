"""CVSS and OWASP Risk Rating calculator tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_calculator_tools(mcp: FastMCP) -> None:
    """Register calculator tools."""

    @mcp.tool(
        description="Calculate CVSS scores from a CVSS vector string",
        tags=[Scopes.SYSTEM_CALCULATOR],
    )
    async def calculate_cvss(
        vector: Annotated[
            str,
            Field(
                description="CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
            ),
        ],
    ) -> dict:
        """
        Calculate CVSS scores from a vector string.

        Returns the base score, impact sub-score, and exploitability sub-score.
        Supports CVSS v2, v3.0, and v3.1 vectors.
        """
        try:
            client = get_client()
            data = await client.get("/calculator/cvss", params={"vector": vector})
            return {"cvss": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Calculate OWASP Risk Rating scores",
        tags=[Scopes.SYSTEM_CALCULATOR],
    )
    async def calculate_owasp_rr(
        vector: Annotated[
            str,
            Field(
                description="OWASP Risk Rating vector string (e.g., SL:5/M:5/O:5/S:5/ED:5/EE:5/A:5/ID:5/LC:5/LI:5/LAV:5/LAC:5/FD:5/RD:5/NC:5/PV:5)"
            ),
        ],
    ) -> dict:
        """
        Calculate OWASP Risk Rating scores from a vector string.

        Returns the likelihood score, technical impact score, and business impact score.

        Vector components:
        - Threat Agent Factors: SL (Skill Level), M (Motive), O (Opportunity), S (Size)
        - Vulnerability Factors: ED (Ease of Discovery), EE (Ease of Exploit), A (Awareness), ID (Intrusion Detection)
        - Technical Impact: LC (Loss of Confidentiality), LI (Loss of Integrity), LAV (Loss of Availability), LAC (Loss of Accountability)
        - Business Impact: FD (Financial Damage), RD (Reputation Damage), NC (Non-Compliance), PV (Privacy Violation)
        """
        try:
            client = get_client()
            data = await client.get("/calculator/owasp", params={"vector": vector})
            return {"owaspRR": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
