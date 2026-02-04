"""Policy violation tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_policy_tools(mcp: FastMCP) -> None:
    """Register policy violation tools."""

    @mcp.tool(
        description="List all policy violations across the portfolio",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_policy_violations(
        suppressed: Annotated[bool, Field(description="Include suppressed violations")] = False,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List all policy violations across the portfolio.

        Returns violations categorized by type:
        - LICENSE: License compatibility violations
        - SECURITY: Security policy violations (e.g., CVSS thresholds)
        - OPERATIONAL: Operational policy violations
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
                "suppressed": str(suppressed).lower(),
            }
            data, headers = await client.get_with_headers("/violation", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "violations": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List policy violations for a specific project",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_project_policy_violations(
        project_uuid: Annotated[str, Field(description="Project UUID")],
        suppressed: Annotated[bool, Field(description="Include suppressed violations")] = False,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List policy violations for a specific project.

        Returns all policy violations affecting components in the project,
        including violation type, severity, and the triggering policy condition.
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
                "suppressed": str(suppressed).lower(),
            }
            data, headers = await client.get_with_headers(
                f"/violation/project/{project_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "violations": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List policy violations for a specific component",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_component_policy_violations(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        suppressed: Annotated[bool, Field(description="Include suppressed violations")] = False,
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List policy violations for a specific component.

        Returns all policy violations triggered by this component
        including license, security, and operational violations.
        """
        try:
            client = get_client()
            params = {
                "pageNumber": page,
                "pageSize": page_size,
                "suppressed": str(suppressed).lower(),
            }
            data, headers = await client.get_with_headers(
                f"/violation/component/{component_uuid}", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "violations": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List all security policies",
        tags=[Scopes.READ_POLICIES],
    )
    async def list_policies(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List all security policies defined in Dependency Track.

        Policies define rules that trigger violations based on:
        - License conditions (forbidden/allowed licenses)
        - Security conditions (CVSS thresholds, specific CVEs)
        - Operational conditions (component age, coordinates)
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/policy", params=params)
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
        description="Get a specific policy by UUID",
        tags=[Scopes.READ_POLICIES],
    )
    async def get_policy(
        uuid: Annotated[str, Field(description="Policy UUID")],
    ) -> dict:
        """
        Get detailed information about a specific policy.

        Returns policy details including conditions, assigned projects, and tags.
        """
        try:
            client = get_client()
            data = await client.get(f"/policy/{uuid}")
            return {"policy": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new security policy",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def create_policy(
        name: Annotated[str, Field(description="Policy name")],
        operator: Annotated[
            str,
            Field(description="Condition operator: ANY (match any) or ALL (match all)"),
        ] = "ANY",
        violation_state: Annotated[
            str,
            Field(description="Violation state: INFO, WARN, or FAIL"),
        ] = "WARN",
        include_children: Annotated[
            bool,
            Field(description="Apply policy to child projects"),
        ] = False,
    ) -> dict:
        """
        Create a new security policy.

        After creating, use create_policy_condition to add conditions.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "operator": operator,
                "violationState": violation_state,
                "includeChildren": include_children,
            }

            data = await client.put("/policy", data=payload)
            return {"policy": data, "message": "Policy created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing policy",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def update_policy(
        uuid: Annotated[str, Field(description="Policy UUID")],
        name: Annotated[str | None, Field(description="New policy name")] = None,
        operator: Annotated[
            str | None,
            Field(description="New condition operator: ANY or ALL"),
        ] = None,
        violation_state: Annotated[
            str | None,
            Field(description="New violation state: INFO, WARN, or FAIL"),
        ] = None,
        include_children: Annotated[
            bool | None,
            Field(description="Apply policy to child projects"),
        ] = None,
    ) -> dict:
        """
        Update an existing policy's properties.
        """
        try:
            client = get_client()

            # Get existing policy
            existing = await client.get(f"/policy/{uuid}")

            # Update fields
            if name is not None:
                existing["name"] = name
            if operator is not None:
                existing["operator"] = operator
            if violation_state is not None:
                existing["violationState"] = violation_state
            if include_children is not None:
                existing["includeChildren"] = include_children

            data = await client.post("/policy", data=existing)
            return {"policy": data, "message": "Policy updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a policy",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def delete_policy(
        uuid: Annotated[str, Field(description="Policy UUID")],
    ) -> dict:
        """
        Delete a security policy.

        This removes the policy and all its conditions.
        """
        try:
            client = get_client()
            await client.delete(f"/policy/{uuid}")
            return {"message": f"Policy {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new policy condition",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def create_policy_condition(
        policy_uuid: Annotated[str, Field(description="Policy UUID")],
        subject: Annotated[
            str,
            Field(
                description="Condition subject: AGE, "
                "COORDINATES, CPE, CWE, HASH, LICENSE, "
                "LICENSE_GROUP, PACKAGE_URL, SEVERITY, "
                "SWID_TAGID, VERSION, COMPONENT_HASH, "
                "VULNERABILITY_ID"
            ),
        ],
        operator: Annotated[
            str,
            Field(
                description="Condition operator: IS, IS_NOT, "
                "MATCHES, NO_MATCH, NUMERIC_GREATER_THAN, "
                "NUMERIC_LESS_THAN, NUMERIC_EQUAL, "
                "NUMERIC_NOT_EQUAL, "
                "NUMERIC_GREATER_THAN_OR_EQUAL, "
                "NUMERIC_LESSER_THAN_OR_EQUAL, "
                "CONTAINS_ALL, CONTAINS_ANY"
            ),
        ],
        value: Annotated[str, Field(description="Condition value to match against")],
    ) -> dict:
        """
        Create a new condition for a policy.

        Conditions define when a policy triggers a violation.
        """
        try:
            client = get_client()
            payload = {
                "subject": subject,
                "operator": operator,
                "value": value,
            }

            data = await client.put(f"/policy/{policy_uuid}/condition", data=payload)
            return {"condition": data, "message": "Policy condition created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update an existing policy condition",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def update_policy_condition(
        uuid: Annotated[str, Field(description="Condition UUID")],
        subject: Annotated[str | None, Field(description="New condition subject")] = None,
        operator: Annotated[str | None, Field(description="New condition operator")] = None,
        value: Annotated[str | None, Field(description="New condition value")] = None,
    ) -> dict:
        """
        Update an existing policy condition.
        """
        try:
            client = get_client()
            payload = {"uuid": uuid}

            if subject is not None:
                payload["subject"] = subject
            if operator is not None:
                payload["operator"] = operator
            if value is not None:
                payload["value"] = value

            data = await client.post("/policy/condition", data=payload)
            return {"condition": data, "message": "Policy condition updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a policy condition",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def delete_policy_condition(
        uuid: Annotated[str, Field(description="Condition UUID")],
    ) -> dict:
        """
        Delete a policy condition.
        """
        try:
            client = get_client()
            await client.delete(f"/policy/condition/{uuid}")
            return {"message": f"Policy condition {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Assign a project to a policy",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def add_project_to_policy(
        policy_uuid: Annotated[str, Field(description="Policy UUID")],
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Assign a project to a policy.

        The policy will then apply to the specified project.
        """
        try:
            client = get_client()
            await client.post(f"/policy/{policy_uuid}/project/{project_uuid}")
            return {"message": "Project added to policy successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a project from a policy",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def remove_project_from_policy(
        policy_uuid: Annotated[str, Field(description="Policy UUID")],
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Remove a project from a policy.

        The policy will no longer apply to the specified project.
        """
        try:
            client = get_client()
            await client.delete(f"/policy/{policy_uuid}/project/{project_uuid}")
            return {"message": "Project removed from policy successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add a tag to a policy",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def add_tag_to_policy(
        policy_uuid: Annotated[str, Field(description="Policy UUID")],
        tag_name: Annotated[str, Field(description="Tag name")],
    ) -> dict:
        """
        Add a tag to a policy.

        The policy will apply to all projects with the specified tag.
        """
        try:
            client = get_client()
            await client.post(f"/policy/{policy_uuid}/tag/{tag_name}")
            return {"message": "Tag added to policy successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a tag from a policy",
        tags=[Scopes.WRITE_POLICIES],
    )
    async def remove_tag_from_policy(
        policy_uuid: Annotated[str, Field(description="Policy UUID")],
        tag_name: Annotated[str, Field(description="Tag name")],
    ) -> dict:
        """
        Remove a tag from a policy.

        The policy will no longer apply to projects with the specified tag.
        """
        try:
            client = get_client()
            await client.delete(f"/policy/{policy_uuid}/tag/{tag_name}")
            return {"message": "Tag removed from policy successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get violation analysis for a component-policy combination",
        tags=[Scopes.READ_POLICIES],
    )
    async def get_violation_analysis(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        policy_violation_uuid: Annotated[str, Field(description="Policy violation UUID")],
    ) -> dict:
        """
        Get the analysis decision for a specific policy violation.

        Returns the current analysis state and any suppression decision.
        """
        try:
            client = get_client()
            data = await client.get(
                "/violation/analysis",
                params={
                    "component": component_uuid,
                    "policyViolation": policy_violation_uuid,
                },
            )
            return {"analysis": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Record an analysis decision for a policy violation",
        tags=[Scopes.WRITE_ANALYSIS],
    )
    async def update_violation_analysis(
        component_uuid: Annotated[str, Field(description="Component UUID")],
        policy_violation_uuid: Annotated[str, Field(description="Policy violation UUID")],
        state: Annotated[
            str | None,
            Field(description="Analysis state: APPROVED, REJECTED, NOT_SET"),
        ] = None,
        comment: Annotated[
            str | None,
            Field(description="Comment to add to the analysis trail"),
        ] = None,
        suppressed: Annotated[
            bool | None,
            Field(description="Suppress this violation"),
        ] = None,
    ) -> dict:
        """
        Record an analysis decision for a policy violation.

        Used to approve, reject, or suppress policy violations.
        """
        try:
            client = get_client()
            payload = {
                "component": component_uuid,
                "policyViolation": policy_violation_uuid,
            }

            if state is not None:
                payload["analysisState"] = state
            if comment is not None:
                payload["comment"] = comment
            if suppressed is not None:
                payload["isSuppressed"] = suppressed

            data = await client.put("/violation/analysis", data=payload)
            return {"analysis": data, "message": "Violation analysis recorded successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
