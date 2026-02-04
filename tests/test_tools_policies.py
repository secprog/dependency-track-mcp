"""Tests for policy violation tools."""

from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.policies import register_policy_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register policy tools."""
    register_policy_tools(mcp)
    return mcp


class TestListPolicyViolationsTool:
    """Tests for list_policy_violations tool."""

    @pytest.mark.asyncio
    async def test_list_violations_success(self, register_tools):
        """Test listing policy violations."""
        mock_data = [
            {
                "uuid": "viol-1",
                "type": "SECURITY",
                "component": {"name": "lodash"},
            }
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_policy_violations")
            assert tool is not None
            result = await tool.fn(suppressed=True)

            assert "violations" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_violations_error(self, register_tools):
        """Test list_policy_violations error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_policy_violations")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestListProjectPolicyViolationsTool:
    """Tests for list_project_policy_violations tool."""

    @pytest.mark.asyncio
    async def test_list_project_violations_success(self, register_tools):
        """Test listing project policy violations."""
        mock_data = [
            {
                "uuid": "viol-1",
                "type": "LICENSE",
                "component": {"name": "lodash"},
            }
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_policy_violations")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "violations" in result

    @pytest.mark.asyncio
    async def test_list_project_violations_error(self, register_tools):
        """Test list_project_policy_violations error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_project_policy_violations")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1")

            assert "error" in result


class TestListComponentPolicyViolationsTool:
    """Tests for list_component_policy_violations tool."""

    @pytest.mark.asyncio
    async def test_list_component_violations_success(self, register_tools):
        """Test listing component policy violations."""
        mock_data = [{"uuid": "viol-1", "type": "OPERATIONAL"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_component_policy_violations")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "violations" in result

    @pytest.mark.asyncio
    async def test_list_component_violations_error(self, register_tools):
        """Test list_component_policy_violations error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_component_policy_violations")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result


class TestListPoliciesTool:
    """Tests for list_policies tool."""

    @pytest.mark.asyncio
    async def test_list_policies_success(self, register_tools):
        """Test listing policies."""
        mock_data = [{"uuid": "policy-1", "name": "Security Policy"}]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_data, {"X-Total-Count": "1"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_policies")
            assert tool is not None
            result = await tool.fn()

            assert "policies" in result
            assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_list_policies_error(self, register_tools):
        """Test list_policies error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_policies")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result


class TestGetPolicyTool:
    """Tests for get_policy tool."""

    @pytest.mark.asyncio
    async def test_get_policy_success(self, register_tools):
        """Test get_policy."""
        mock_data = {"uuid": "policy-1", "name": "Security Policy"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_policy")
            assert tool is not None
            result = await tool.fn(uuid="policy-1")

            assert "policy" in result

    @pytest.mark.asyncio
    async def test_get_policy_error(self, register_tools):
        """Test get_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_policy")
            assert tool is not None
            result = await tool.fn(uuid="policy-1")

            assert "error" in result


class TestCreatePolicyTool:
    """Tests for create_policy tool."""

    @pytest.mark.asyncio
    async def test_create_policy_success(self, register_tools):
        """Test create_policy."""
        mock_data = {"uuid": "policy-1", "name": "New Policy"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_policy")
            assert tool is not None
            result = await tool.fn(name="New Policy", operator="ALL", violation_state="FAIL")

            assert "policy" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_create_policy_error(self, register_tools):
        """Test create_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_policy")
            assert tool is not None
            result = await tool.fn(name="New Policy")

            assert "error" in result


class TestUpdatePolicyTool:
    """Tests for update_policy tool."""

    @pytest.mark.asyncio
    async def test_update_policy_success(self, register_tools):
        """Test update_policy."""
        existing_data = {"uuid": "policy-1", "name": "Old Name", "operator": "ANY"}
        updated_data = {"uuid": "policy-1", "name": "New Name", "operator": "ALL"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=existing_data)
            mock_client.post = AsyncMock(return_value=updated_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_policy")
            assert tool is not None
            result = await tool.fn(uuid="policy-1", name="New Name", operator="ALL")

            assert "policy" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_policy_error(self, register_tools):
        """Test update_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_policy")
            assert tool is not None
            result = await tool.fn(uuid="policy-1", name="New Name")

            assert "error" in result


class TestDeletePolicyTool:
    """Tests for delete_policy tool."""

    @pytest.mark.asyncio
    async def test_delete_policy_success(self, register_tools):
        """Test delete_policy."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_policy")
            assert tool is not None
            result = await tool.fn(uuid="policy-1")

            assert "message" in result

    @pytest.mark.asyncio
    async def test_delete_policy_error(self, register_tools):
        """Test delete_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_policy")
            assert tool is not None
            result = await tool.fn(uuid="policy-1")

            assert "error" in result


class TestPolicyConditionTools:
    """Tests for policy condition tools."""

    @pytest.mark.asyncio
    async def test_create_policy_condition_success(self, register_tools):
        """Test create_policy_condition."""
        mock_data = {"uuid": "cond-1", "subject": "SEVERITY", "operator": "IS", "value": "CRITICAL"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_policy_condition")
            assert tool is not None
            result = await tool.fn(
                policy_uuid="policy-1", subject="SEVERITY", operator="IS", value="CRITICAL"
            )

            assert "condition" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_create_policy_condition_error(self, register_tools):
        """Test create_policy_condition error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "create_policy_condition")
            assert tool is not None
            result = await tool.fn(
                policy_uuid="policy-1", subject="SEVERITY", operator="IS", value="CRITICAL"
            )

            assert "error" in result

    @pytest.mark.asyncio
    async def test_update_policy_condition_success(self, register_tools):
        """Test update_policy_condition."""
        mock_data = {"uuid": "cond-1", "value": "HIGH"}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_policy_condition")
            assert tool is not None
            result = await tool.fn(uuid="cond-1", value="HIGH")

            assert "condition" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_policy_condition_error(self, register_tools):
        """Test update_policy_condition error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_policy_condition")
            assert tool is not None
            result = await tool.fn(uuid="cond-1", value="HIGH")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_delete_policy_condition_success(self, register_tools):
        """Test delete_policy_condition."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_policy_condition")
            assert tool is not None
            result = await tool.fn(uuid="cond-1")

            assert "message" in result

    @pytest.mark.asyncio
    async def test_delete_policy_condition_error(self, register_tools):
        """Test delete_policy_condition error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "delete_policy_condition")
            assert tool is not None
            result = await tool.fn(uuid="cond-1")

            assert "error" in result


class TestPolicyProjectAssignmentTools:
    """Tests for policy-project assignment tools."""

    @pytest.mark.asyncio
    async def test_add_project_to_policy_success(self, register_tools):
        """Test add_project_to_policy."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_project_to_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", project_uuid="proj-1")

            assert "message" in result

    @pytest.mark.asyncio
    async def test_add_project_to_policy_error(self, register_tools):
        """Test add_project_to_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_project_to_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", project_uuid="proj-1")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_remove_project_from_policy_success(self, register_tools):
        """Test remove_project_from_policy."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_project_from_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", project_uuid="proj-1")

            assert "message" in result

    @pytest.mark.asyncio
    async def test_remove_project_from_policy_error(self, register_tools):
        """Test remove_project_from_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_project_from_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", project_uuid="proj-1")

            assert "error" in result


class TestPolicyTagTools:
    """Tests for policy tag tools."""

    @pytest.mark.asyncio
    async def test_add_tag_to_policy_success(self, register_tools):
        """Test add_tag_to_policy."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_tag_to_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", tag_name="production")

            assert "message" in result

    @pytest.mark.asyncio
    async def test_add_tag_to_policy_error(self, register_tools):
        """Test add_tag_to_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_tag_to_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", tag_name="production")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_remove_tag_from_policy_success(self, register_tools):
        """Test remove_tag_from_policy."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_tag_from_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", tag_name="production")

            assert "message" in result

    @pytest.mark.asyncio
    async def test_remove_tag_from_policy_error(self, register_tools):
        """Test remove_tag_from_policy error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_tag_from_policy")
            assert tool is not None
            result = await tool.fn(policy_uuid="policy-1", tag_name="production")

            assert "error" in result


class TestViolationAnalysisTools:
    """Tests for violation analysis tools."""

    @pytest.mark.asyncio
    async def test_get_violation_analysis_success(self, register_tools):
        """Test get_violation_analysis."""
        mock_data = {"state": "APPROVED", "suppressed": False}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_violation_analysis")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", policy_violation_uuid="viol-1")

            assert "analysis" in result

    @pytest.mark.asyncio
    async def test_get_violation_analysis_error(self, register_tools):
        """Test get_violation_analysis error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_violation_analysis")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", policy_violation_uuid="viol-1")

            assert "error" in result

    @pytest.mark.asyncio
    async def test_update_violation_analysis_success(self, register_tools):
        """Test update_violation_analysis."""
        mock_data = {"state": "REJECTED", "suppressed": True}

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_violation_analysis")
            assert tool is not None
            result = await tool.fn(
                component_uuid="comp-1",
                policy_violation_uuid="viol-1",
                state="REJECTED",
                comment="False positive",
                suppressed=True,
            )

            assert "analysis" in result
            assert "message" in result

    @pytest.mark.asyncio
    async def test_update_violation_analysis_error(self, register_tools):
        """Test update_violation_analysis error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "update_violation_analysis")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1", policy_violation_uuid="viol-1")

            assert "error" in result
