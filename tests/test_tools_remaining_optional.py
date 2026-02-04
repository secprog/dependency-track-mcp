"""
Tests for remaining optional field coverage.
Targets lines in notifications, policies, and projects optional field handling.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.tools.notifications import register_notification_tools
from dependency_track_mcp.tools.policies import register_policy_tools
from dependency_track_mcp.tools.projects import register_project_tools
from tests.utils import find_tool


@pytest.fixture
def notification_tools(mcp):
    """Register notification tools."""
    register_notification_tools(mcp)
    return mcp


@pytest.fixture
def policy_tools(mcp):
    """Register policy tools."""
    register_policy_tools(mcp)
    return mcp


@pytest.fixture
def project_tools(mcp):
    """Register project tools."""
    register_project_tools(mcp)
    return mcp


class TestNotificationPublisherOptionalFields:
    """Tests for notification publisher optional field handling."""

    @pytest.mark.asyncio
    async def test_update_notification_publisher_with_template(self, notification_tools):
        """Test updating publisher with template field."""
        updated_data = {
            "uuid": "pub-1",
            "name": "Test",
            "template": "new-template",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(notification_tools, "update_notification_publisher")
            assert tool is not None
            result = await tool.fn(uuid="pub-1", template="new-template")

            assert "publisher" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["template"] == "new-template"

    @pytest.mark.asyncio
    async def test_update_notification_publisher_with_mime_type(self, notification_tools):
        """Test updating publisher with template_mime_type field."""
        updated_data = {
            "uuid": "pub-1",
            "templateMimeType": "application/json",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(notification_tools, "update_notification_publisher")
            assert tool is not None
            result = await tool.fn(uuid="pub-1", template_mime_type="application/json")

            assert "publisher" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["templateMimeType"] == "application/json"

    @pytest.mark.asyncio
    async def test_update_notification_publisher_with_default(self, notification_tools):
        """Test updating publisher with default_publisher field."""
        updated_data = {
            "uuid": "pub-1",
            "defaultPublisher": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(notification_tools, "update_notification_publisher")
            assert tool is not None
            result = await tool.fn(uuid="pub-1", default_publisher=True)

            assert "publisher" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["defaultPublisher"] is True

    @pytest.mark.asyncio
    async def test_update_notification_publisher_all_optional(self, notification_tools):
        """Test updating publisher with all optional fields."""
        updated_data = {
            "uuid": "pub-1",
            "name": "New Name",
            "template": "template-content",
            "templateMimeType": "text/plain",
            "defaultPublisher": False,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(notification_tools, "update_notification_publisher")
            assert tool is not None
            result = await tool.fn(
                uuid="pub-1",
                name="New Name",
                template="template-content",
                template_mime_type="text/plain",
                default_publisher=False,
            )

            assert "publisher" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["name"] == "New Name"
            assert posted_data["template"] == "template-content"
            assert posted_data["templateMimeType"] == "text/plain"
            assert posted_data["defaultPublisher"] is False


class TestNotificationRuleOptionalFields:
    """Tests for notification rule optional field handling."""

    @pytest.mark.asyncio
    async def test_update_notification_rule_with_level(self, notification_tools):
        """Test updating rule with notification_level field."""
        updated_data = {
            "uuid": "rule-1",
            "notificationLevel": "HIGH",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(notification_tools, "update_notification_rule")
            assert tool is not None
            result = await tool.fn(uuid="rule-1", notification_level="HIGH")

            assert "rule" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["notificationLevel"] == "HIGH"

    @pytest.mark.asyncio
    async def test_update_notification_rule_with_enabled(self, notification_tools):
        """Test updating rule with enabled field."""
        updated_data = {
            "uuid": "rule-1",
            "enabled": False,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(notification_tools, "update_notification_rule")
            assert tool is not None
            result = await tool.fn(uuid="rule-1", enabled=False)

            assert "rule" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["enabled"] is False

    @pytest.mark.asyncio
    async def test_update_notification_rule_all_optional(self, notification_tools):
        """Test updating rule with all optional fields."""
        updated_data = {
            "uuid": "rule-1",
            "name": "New Rule",
            "notificationLevel": "MEDIUM",
            "enabled": True,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(notification_tools, "update_notification_rule")
            assert tool is not None
            result = await tool.fn(
                uuid="rule-1",
                name="New Rule",
                notification_level="MEDIUM",
                enabled=True,
            )

            assert "rule" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["name"] == "New Rule"
            assert posted_data["notificationLevel"] == "MEDIUM"
            assert posted_data["enabled"] is True


class TestPolicyOptionalFields:
    """Tests for policy optional field handling."""

    @pytest.mark.asyncio
    async def test_update_policy_with_operator(self, policy_tools):
        """Test updating policy with operator field."""
        existing = {"uuid": "pol-1", "operator": "AND"}
        updated = {"uuid": "pol-1", "operator": "OR"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=updated)
            mock_get_instance.return_value = mock_client

            tool = find_tool(policy_tools, "update_policy")
            assert tool is not None
            result = await tool.fn(uuid="pol-1", operator="OR")

            assert "policy" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["operator"] == "OR"

    @pytest.mark.asyncio
    async def test_update_policy_with_violation_state(self, policy_tools):
        """Test updating policy with violation_state field."""
        existing = {"uuid": "pol-1", "violationState": "INFO"}
        updated = {"uuid": "pol-1", "violationState": "FAIL"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=updated)
            mock_get_instance.return_value = mock_client

            tool = find_tool(policy_tools, "update_policy")
            assert tool is not None
            result = await tool.fn(uuid="pol-1", violation_state="FAIL")

            assert "policy" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["violationState"] == "FAIL"

    @pytest.mark.asyncio
    async def test_update_policy_with_include_children(self, policy_tools):
        """Test updating policy with include_children field."""
        existing = {"uuid": "pol-1", "includeChildren": False}
        updated = {"uuid": "pol-1", "includeChildren": True}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing)
            mock_client.post = AsyncMock(return_value=updated)
            mock_get_instance.return_value = mock_client

            tool = find_tool(policy_tools, "update_policy")
            assert tool is not None
            result = await tool.fn(uuid="pol-1", include_children=True)

            assert "policy" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["includeChildren"] is True

    @pytest.mark.asyncio
    async def test_update_policy_condition_with_subject(self, policy_tools):
        """Test updating policy condition with subject field."""
        updated_data = {
            "uuid": "cond-1",
            "subject": "new-subject",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(policy_tools, "update_policy_condition")
            assert tool is not None
            result = await tool.fn(uuid="cond-1", subject="new-subject")

            assert "condition" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["subject"] == "new-subject"

    @pytest.mark.asyncio
    async def test_update_policy_condition_with_operator(self, policy_tools):
        """Test updating policy condition with operator field."""
        updated_data = {
            "uuid": "cond-1",
            "operator": "MATCHES",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(policy_tools, "update_policy_condition")
            assert tool is not None
            result = await tool.fn(uuid="cond-1", operator="MATCHES")

            assert "condition" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["operator"] == "MATCHES"

    @pytest.mark.asyncio
    async def test_update_policy_condition_with_value(self, policy_tools):
        """Test updating policy condition with value field."""
        updated_data = {
            "uuid": "cond-1",
            "value": "new-value",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(policy_tools, "update_policy_condition")
            assert tool is not None
            result = await tool.fn(uuid="cond-1", value="new-value")

            assert "condition" in result
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["value"] == "new-value"


class TestProjectOptionalFields:
    """Tests for project optional field handling."""

    @pytest.mark.asyncio
    async def test_patch_project_with_description(self, project_tools):
        """Test patching project with description field."""
        updated_data = {
            "uuid": "proj-1",
            "description": "new description",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.patch = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(project_tools, "patch_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", description="new description")

            assert "project" in result
            call_args = mock_client.patch.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["description"] == "new description"

    @pytest.mark.asyncio
    async def test_patch_project_with_active(self, project_tools):
        """Test patching project with active field."""
        updated_data = {
            "uuid": "proj-1",
            "active": False,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.patch = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(project_tools, "patch_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", active=False)

            assert "project" in result
            call_args = mock_client.patch.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["active"] is False

    @pytest.mark.asyncio
    async def test_patch_project_with_classifier(self, project_tools):
        """Test patching project with classifier field."""
        updated_data = {
            "uuid": "proj-1",
            "classifier": "FRAMEWORK",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.patch = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(project_tools, "patch_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", classifier="FRAMEWORK")

            assert "project" in result
            call_args = mock_client.patch.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["classifier"] == "FRAMEWORK"

    @pytest.mark.asyncio
    async def test_patch_project_with_tags(self, project_tools):
        """Test patching project with tags field."""
        updated_data = {
            "uuid": "proj-1",
            "tags": [{"name": "tag1"}, {"name": "tag2"}],
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.patch = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(project_tools, "patch_project")
            assert tool is not None
            result = await tool.fn(uuid="proj-1", tags=["tag1", "tag2"])

            assert "project" in result
            call_args = mock_client.patch.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["tags"] == [{"name": "tag1"}, {"name": "tag2"}]

    @pytest.mark.asyncio
    async def test_patch_project_all_optional(self, project_tools):
        """Test patching project with all optional fields."""
        updated_data = {
            "uuid": "proj-1",
            "name": "New Name",
            "version": "2.0.0",
            "description": "New description",
            "active": True,
            "classifier": "APPLICATION",
            "tags": [{"name": "prod"}],
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.patch = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(project_tools, "patch_project")
            assert tool is not None
            result = await tool.fn(
                uuid="proj-1",
                name="New Name",
                version="2.0.0",
                description="New description",
                active=True,
                classifier="APPLICATION",
                tags=["prod"],
            )

            assert "project" in result
            call_args = mock_client.patch.call_args
            posted_data = call_args[1]["data"]
            assert posted_data["name"] == "New Name"
            assert posted_data["version"] == "2.0.0"
            assert posted_data["description"] == "New description"
            assert posted_data["active"] is True
            assert posted_data["classifier"] == "APPLICATION"
            assert posted_data["tags"] == [{"name": "prod"}]
