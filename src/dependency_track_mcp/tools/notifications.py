"""Notification management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_notification_tools(mcp: FastMCP) -> None:
    """Register notification management tools."""

    @mcp.tool(
        description="List all notification publishers",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def list_notification_publishers(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all notification publishers.

        Publishers define how notifications are delivered (email, webhook, etc.).
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                "/notification/publisher", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "publishers": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a notification publisher",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def create_notification_publisher(
        name: Annotated[str, Field(description="Publisher name")],
        publisher_class: Annotated[
            str,
            Field(
                description="Publisher class: SLACK, MS_TEAMS, MATTERMOST, EMAIL, CONSOLE, WEBHOOK, JIRA"
            ),
        ],
        template: Annotated[str, Field(description="Notification template content")],
        template_mime_type: Annotated[
            str, Field(description="Template MIME type (e.g., application/json)")
        ] = "application/json",
        default_publisher: Annotated[
            bool, Field(description="Set as default publisher")
        ] = False,
    ) -> dict:
        """
        Create a new notification publisher.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "publisherClass": publisher_class,
                "template": template,
                "templateMimeType": template_mime_type,
                "defaultPublisher": default_publisher,
            }

            data = await client.put("/notification/publisher", data=payload)
            return {"publisher": data, "message": "Publisher created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update a notification publisher",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def update_notification_publisher(
        uuid: Annotated[str, Field(description="Publisher UUID")],
        name: Annotated[str | None, Field(description="New name")] = None,
        template: Annotated[str | None, Field(description="New template")] = None,
        template_mime_type: Annotated[
            str | None, Field(description="New MIME type")
        ] = None,
        default_publisher: Annotated[
            bool | None, Field(description="Set as default")
        ] = None,
    ) -> dict:
        """
        Update a notification publisher.
        """
        try:
            client = get_client()
            payload = {"uuid": uuid}

            if name is not None:
                payload["name"] = name
            if template is not None:
                payload["template"] = template
            if template_mime_type is not None:
                payload["templateMimeType"] = template_mime_type
            if default_publisher is not None:
                payload["defaultPublisher"] = default_publisher

            data = await client.post("/notification/publisher", data=payload)
            return {"publisher": data, "message": "Publisher updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a notification publisher",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def delete_notification_publisher(
        uuid: Annotated[str, Field(description="Publisher UUID")],
    ) -> dict:
        """
        Delete a notification publisher and all its associated rules.
        """
        try:
            client = get_client()
            await client.delete(f"/notification/publisher/{uuid}")
            return {"message": f"Publisher {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Restore default notification publisher templates",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def restore_default_templates() -> dict:
        """
        Restore the default notification publisher templates.

        This resets all publisher templates to their original defaults.
        """
        try:
            client = get_client()
            await client.post("/notification/publisher/restoreDefaultTemplates")
            return {"message": "Default templates restored successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Test SMTP notification",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def test_smtp_notification(
        destination: Annotated[str, Field(description="Email address to send test to")],
    ) -> dict:
        """
        Send a test SMTP notification to verify email configuration.
        """
        try:
            client = get_client()
            await client.post(
                "/notification/publisher/test/smtp",
                data={"destination": destination},
            )
            return {"message": f"Test notification sent to {destination}"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Test a notification publisher",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def test_notification_publisher(
        publisher_uuid: Annotated[str, Field(description="Publisher UUID to test")],
    ) -> dict:
        """
        Send a test notification using a specific publisher.
        """
        try:
            client = get_client()
            await client.post(f"/notification/publisher/test/{publisher_uuid}")
            return {"message": "Test notification dispatched successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List all notification rules",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def list_notification_rules(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[
            int, Field(ge=1, le=100, description="Items per page")
        ] = 100,
    ) -> dict:
        """
        List all notification rules.

        Rules define which events trigger notifications and to which publishers.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers(
                "/notification/rule", params=params
            )
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "rules": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def create_notification_rule(
        name: Annotated[str, Field(description="Rule name")],
        publisher_uuid: Annotated[str, Field(description="Publisher UUID")],
        scope: Annotated[
            str,
            Field(
                description="Notification scope: PORTFOLIO, SYSTEM"
            ),
        ],
        notification_level: Annotated[
            str, Field(description="Notification level: INFORMATIONAL, WARNING, ERROR")
        ] = "INFORMATIONAL",
        enabled: Annotated[bool, Field(description="Enable the rule")] = True,
    ) -> dict:
        """
        Create a new notification rule.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "publisher": {"uuid": publisher_uuid},
                "scope": scope,
                "notificationLevel": notification_level,
                "enabled": enabled,
            }

            data = await client.put("/notification/rule", data=payload)
            return {"rule": data, "message": "Notification rule created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a scheduled notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def create_scheduled_notification_rule(
        name: Annotated[str, Field(description="Rule name")],
        publisher_uuid: Annotated[str, Field(description="Publisher UUID")],
        cron_config: Annotated[str, Field(description="Cron expression for schedule")],
        publish_only_with_updates: Annotated[
            bool, Field(description="Only publish when there are updates")
        ] = True,
        enabled: Annotated[bool, Field(description="Enable the rule")] = True,
    ) -> dict:
        """
        Create a scheduled notification rule.

        Scheduled rules run on a cron schedule rather than being triggered by events.
        """
        try:
            client = get_client()
            payload = {
                "name": name,
                "publisher": {"uuid": publisher_uuid},
                "scope": "PORTFOLIO",
                "cronConfig": cron_config,
                "publishOnlyWithUpdates": publish_only_with_updates,
                "enabled": enabled,
            }

            data = await client.put("/notification/rule/scheduled", data=payload)
            return {"rule": data, "message": "Scheduled rule created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update a notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def update_notification_rule(
        uuid: Annotated[str, Field(description="Rule UUID")],
        name: Annotated[str | None, Field(description="New name")] = None,
        notification_level: Annotated[
            str | None, Field(description="New notification level")
        ] = None,
        enabled: Annotated[bool | None, Field(description="Enable/disable")] = None,
    ) -> dict:
        """
        Update a notification rule.
        """
        try:
            client = get_client()
            payload = {"uuid": uuid}

            if name is not None:
                payload["name"] = name
            if notification_level is not None:
                payload["notificationLevel"] = notification_level
            if enabled is not None:
                payload["enabled"] = enabled

            data = await client.post("/notification/rule", data=payload)
            return {"rule": data, "message": "Rule updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def delete_notification_rule(
        uuid: Annotated[str, Field(description="Rule UUID")],
    ) -> dict:
        """
        Delete a notification rule.
        """
        try:
            client = get_client()
            await client.delete("/notification/rule", params={"uuid": uuid})
            return {"message": f"Rule {uuid} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add a project to a notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def add_project_to_notification_rule(
        rule_uuid: Annotated[str, Field(description="Rule UUID")],
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Add a project to a notification rule.

        The rule will only trigger for events related to this project.
        """
        try:
            client = get_client()
            await client.post(f"/notification/rule/{rule_uuid}/project/{project_uuid}")
            return {"message": "Project added to rule successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a project from a notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def remove_project_from_notification_rule(
        rule_uuid: Annotated[str, Field(description="Rule UUID")],
        project_uuid: Annotated[str, Field(description="Project UUID")],
    ) -> dict:
        """
        Remove a project from a notification rule.
        """
        try:
            client = get_client()
            await client.delete(f"/notification/rule/{rule_uuid}/project/{project_uuid}")
            return {"message": "Project removed from rule successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add a team to a notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def add_team_to_notification_rule(
        rule_uuid: Annotated[str, Field(description="Rule UUID")],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Add a team to a notification rule.

        Members of the team will receive notifications.
        """
        try:
            client = get_client()
            await client.post(f"/notification/rule/{rule_uuid}/team/{team_uuid}")
            return {"message": "Team added to rule successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a team from a notification rule",
        tags=[Scopes.ADMIN_NOTIFICATIONS],
    )
    async def remove_team_from_notification_rule(
        rule_uuid: Annotated[str, Field(description="Rule UUID")],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Remove a team from a notification rule.
        """
        try:
            client = get_client()
            await client.delete(f"/notification/rule/{rule_uuid}/team/{team_uuid}")
            return {"message": "Team removed from rule successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
