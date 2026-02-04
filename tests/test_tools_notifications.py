"""Tests for notification management tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from tests.utils import find_tool


@pytest.fixture
def register_tools():
    """Fixture that registers all tools."""
    from dependency_track_mcp.server import mcp

    return mcp


class TestListNotificationPublishersTool:
    """Tests for list_notification_publishers tool."""

    @pytest.mark.asyncio
    async def test_list_notification_publishers_success(self, register_tools):
        """Test listing all notification publishers."""
        mock_publishers = [
            {"uuid": "pub-1", "name": "Email Publisher", "publisherClass": "EMAIL"},
            {"uuid": "pub-2", "name": "Slack Publisher", "publisherClass": "SLACK"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_publishers, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_notification_publishers")
            assert tool is not None
            result = await tool.fn()

            assert "publishers" in result
            assert result["publishers"] == mock_publishers
            assert result["total"] == 2
            call_args = mock_client.get_with_headers.call_args
            assert "/notification/publisher" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_list_notification_publishers_with_pagination(self, register_tools):
        """Test list_notification_publishers with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "50"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_notification_publishers")
            assert tool is not None
            result = await tool.fn(page=2, page_size=25)

            assert result["page"] == 2
            assert result["page_size"] == 25

    @pytest.mark.asyncio
    async def test_list_notification_publishers_error(self, register_tools):
        """Test list_notification_publishers error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_notification_publishers")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "details" in result


class TestCreateNotificationPublisherTool:
    """Tests for create_notification_publisher tool."""

    @pytest.mark.asyncio
    async def test_create_notification_publisher_success(self, register_tools):
        """Test creating a notification publisher."""
        mock_publisher = {
            "uuid": "pub-new",
            "name": "New Publisher",
            "publisherClass": "WEBHOOK",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_publisher)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_notification_publisher")
            assert tool is not None
            result = await tool.fn(
                name="New Publisher",
                publisher_class="WEBHOOK",
                template='{"url": "https://example.com/webhook"}',
            )

            assert "publisher" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_notification_publisher_with_all_options(self, register_tools):
        """Test create_notification_publisher with all options."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "pub-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_notification_publisher")
            assert tool is not None
            await tool.fn(
                name="Email Publisher",
                publisher_class="EMAIL",
                template="email template",
                template_mime_type="text/plain",
                default_publisher=True,
            )

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["name"] == "Email Publisher"
            assert payload["publisherClass"] == "EMAIL"
            assert payload["defaultPublisher"] is True
            assert payload["templateMimeType"] == "text/plain"

    @pytest.mark.asyncio
    async def test_create_notification_publisher_error(self, register_tools):
        """Test create_notification_publisher error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid template")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_notification_publisher")
            assert tool is not None
            result = await tool.fn(
                name="Bad Publisher",
                publisher_class="WEBHOOK",
                template="invalid",
            )

            assert "error" in result


class TestUpdateNotificationPublisherTool:
    """Tests for update_notification_publisher tool."""

    @pytest.mark.asyncio
    async def test_update_notification_publisher_success(self, register_tools):
        """Test updating a notification publisher."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={"uuid": "pub-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_notification_publisher")
            assert tool is not None
            result = await tool.fn(uuid="pub-1", name="Updated Name")

            assert "publisher" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_notification_publisher_partial(self, register_tools):
        """Test update_notification_publisher with partial updates."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_notification_publisher")
            assert tool is not None
            await tool.fn(uuid="pub-1", default_publisher=True)

            call_args = mock_client.post.call_args
            payload = call_args[1]["data"]
            assert payload["uuid"] == "pub-1"
            assert payload["defaultPublisher"] is True
            assert "name" not in payload

    @pytest.mark.asyncio
    async def test_update_notification_publisher_error(self, register_tools):
        """Test update_notification_publisher error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Publisher not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_notification_publisher")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", name="New Name")

            assert "error" in result


class TestDeleteNotificationPublisherTool:
    """Tests for delete_notification_publisher tool."""

    @pytest.mark.asyncio
    async def test_delete_notification_publisher_success(self, register_tools):
        """Test deleting a notification publisher."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_notification_publisher")
            assert tool is not None
            result = await tool.fn(uuid="pub-1")

            assert "message" in result
            assert "deleted" in result["message"].lower()
            mock_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_notification_publisher_error(self, register_tools):
        """Test delete_notification_publisher error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Publisher not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_notification_publisher")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result


class TestRestoreDefaultTemplatesTool:
    """Tests for restore_default_templates tool."""

    @pytest.mark.asyncio
    async def test_restore_default_templates_success(self, register_tools):
        """Test restoring default templates."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "restore_default_templates")
            assert tool is not None
            result = await tool.fn()

            assert "message" in result
            assert "restored" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_restore_default_templates_error(self, register_tools):
        """Test restore_default_templates error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Operation failed")
            error.details = {"status": 500}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "restore_default_templates")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestTestSmtpNotificationTool:
    """Tests for test_smtp_notification tool."""

    @pytest.mark.asyncio
    async def test_test_smtp_notification_success(self, register_tools):
        """Test sending a test SMTP notification."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "test_smtp_notification")
            assert tool is not None
            result = await tool.fn(destination="test@example.com")

            assert "message" in result
            assert "test@example.com" in result["message"]

    @pytest.mark.asyncio
    async def test_test_smtp_notification_error(self, register_tools):
        """Test test_smtp_notification error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("SMTP not configured")
            error.details = {"status": 400}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "test_smtp_notification")
            assert tool is not None
            result = await tool.fn(destination="test@example.com")

            assert "error" in result


class TestTestNotificationPublisherTool:
    """Tests for test_notification_publisher tool."""

    @pytest.mark.asyncio
    async def test_test_notification_publisher_success(self, register_tools):
        """Test sending a test notification."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "test_notification_publisher")
            assert tool is not None
            result = await tool.fn(publisher_uuid="pub-1")

            assert "message" in result
            assert "dispatched" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_test_notification_publisher_error(self, register_tools):
        """Test test_notification_publisher error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Publisher not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "test_notification_publisher")
            assert tool is not None
            result = await tool.fn(publisher_uuid="bad-uuid")

            assert "error" in result


class TestListNotificationRulesTool:
    """Tests for list_notification_rules tool."""

    @pytest.mark.asyncio
    async def test_list_notification_rules_success(self, register_tools):
        """Test listing all notification rules."""
        mock_rules = [
            {"uuid": "rule-1", "name": "Critical Alerts"},
            {"uuid": "rule-2", "name": "Email Notifications"},
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_rules, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_notification_rules")
            assert tool is not None
            result = await tool.fn()

            assert "rules" in result
            assert result["rules"] == mock_rules
            assert result["total"] == 2

    @pytest.mark.asyncio
    async def test_list_notification_rules_with_pagination(self, register_tools):
        """Test list_notification_rules with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "100"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_notification_rules")
            assert tool is not None
            result = await tool.fn(page=3, page_size=50)

            assert result["page"] == 3
            assert result["total"] == 100

    @pytest.mark.asyncio
    async def test_list_notification_rules_error(self, register_tools):
        """Test list_notification_rules error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Access denied")
            error.details = {"status": 403}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_notification_rules")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestCreateNotificationRuleTool:
    """Tests for create_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_create_notification_rule_success(self, register_tools):
        """Test creating a notification rule."""
        mock_rule = {"uuid": "rule-new", "name": "New Rule"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_rule)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_notification_rule")
            assert tool is not None
            result = await tool.fn(
                name="New Rule",
                publisher_uuid="pub-1",
                scope="PORTFOLIO",
            )

            assert "rule" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_notification_rule_with_all_options(self, register_tools):
        """Test create_notification_rule with all options."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "rule-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_notification_rule")
            assert tool is not None
            await tool.fn(
                name="Error Alerts",
                publisher_uuid="pub-1",
                scope="PORTFOLIO",
                notification_level="ERROR",
                enabled=True,
            )

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["name"] == "Error Alerts"
            assert payload["notificationLevel"] == "ERROR"
            assert payload["enabled"] is True

    @pytest.mark.asyncio
    async def test_create_notification_rule_error(self, register_tools):
        """Test create_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid scope")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_notification_rule")
            assert tool is not None
            result = await tool.fn(
                name="Bad Rule",
                publisher_uuid="pub-1",
                scope="INVALID",
            )

            assert "error" in result


class TestCreateScheduledNotificationRuleTool:
    """Tests for create_scheduled_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_create_scheduled_notification_rule_success(self, register_tools):
        """Test creating a scheduled notification rule."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"uuid": "rule-scheduled"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_scheduled_notification_rule")
            assert tool is not None
            result = await tool.fn(
                name="Daily Report",
                publisher_uuid="pub-1",
                cron_config="0 9 * * MON-FRI",
            )

            assert "rule" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_create_scheduled_notification_rule_payload(self, register_tools):
        """Test create_scheduled_notification_rule sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_scheduled_notification_rule")
            assert tool is not None
            await tool.fn(
                name="Weekly Digest",
                publisher_uuid="pub-1",
                cron_config="0 0 * * SUN",
                publish_only_with_updates=False,
            )

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["cronConfig"] == "0 0 * * SUN"
            assert payload["publishOnlyWithUpdates"] is False

    @pytest.mark.asyncio
    async def test_create_scheduled_notification_rule_error(self, register_tools):
        """Test create_scheduled_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid cron expression")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_scheduled_notification_rule")
            assert tool is not None
            result = await tool.fn(
                name="Bad Rule",
                publisher_uuid="pub-1",
                cron_config="invalid",
            )

            assert "error" in result


class TestUpdateNotificationRuleTool:
    """Tests for update_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_update_notification_rule_success(self, register_tools):
        """Test updating a notification rule."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={"uuid": "rule-1"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_notification_rule")
            assert tool is not None
            result = await tool.fn(uuid="rule-1", enabled=False)

            assert "rule" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_notification_rule_error(self, register_tools):
        """Test update_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Rule not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_notification_rule")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid", enabled=False)

            assert "error" in result


class TestDeleteNotificationRuleTool:
    """Tests for delete_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_delete_notification_rule_success(self, register_tools):
        """Test deleting a notification rule."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_notification_rule")
            assert tool is not None
            result = await tool.fn(uuid="rule-1")

            assert "message" in result
            assert "deleted" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_delete_notification_rule_error(self, register_tools):
        """Test delete_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Rule not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_notification_rule")
            assert tool is not None
            result = await tool.fn(uuid="bad-uuid")

            assert "error" in result


class TestAddProjectToNotificationRuleTool:
    """Tests for add_project_to_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_add_project_to_notification_rule_success(self, register_tools):
        """Test adding a project to a notification rule."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_project_to_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", project_uuid="proj-1")

            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_add_project_to_notification_rule_error(self, register_tools):
        """Test add_project_to_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_project_to_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", project_uuid="proj-1")

            assert "error" in result


class TestRemoveProjectFromNotificationRuleTool:
    """Tests for remove_project_from_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_remove_project_from_notification_rule_success(self, register_tools):
        """Test removing a project from a notification rule."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_project_from_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", project_uuid="proj-1")

            assert "message" in result
            assert "removed" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_remove_project_from_notification_rule_error(self, register_tools):
        """Test remove_project_from_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_project_from_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", project_uuid="proj-1")

            assert "error" in result


class TestAddTeamToNotificationRuleTool:
    """Tests for add_team_to_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_add_team_to_notification_rule_success(self, register_tools):
        """Test adding a team to a notification rule."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_team_to_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", team_uuid="team-1")

            assert "message" in result
            assert "successfully" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_add_team_to_notification_rule_error(self, register_tools):
        """Test add_team_to_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_team_to_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", team_uuid="bad-uuid")

            assert "error" in result


class TestRemoveTeamFromNotificationRuleTool:
    """Tests for remove_team_from_notification_rule tool."""

    @pytest.mark.asyncio
    async def test_remove_team_from_notification_rule_success(self, register_tools):
        """Test removing a team from a notification rule."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_team_from_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", team_uuid="team-1")

            assert "message" in result
            assert "removed" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_remove_team_from_notification_rule_error(self, register_tools):
        """Test remove_team_from_notification_rule error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_team_from_notification_rule")
            assert tool is not None
            result = await tool.fn(rule_uuid="rule-1", team_uuid="team-1")

            assert "error" in result
