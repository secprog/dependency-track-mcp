"""Tests for LDAP integration tools."""

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


class TestListLdapGroupsTool:
    """Tests for list_ldap_groups tool."""

    @pytest.mark.asyncio
    async def test_list_ldap_groups_success(self, register_tools):
        """Test listing LDAP groups."""
        mock_groups = [
            "cn=developers,ou=groups,dc=example,dc=com",
            "cn=admins,ou=groups,dc=example,dc=com",
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(
                return_value=(mock_groups, {"X-Total-Count": "2"})
            )
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_ldap_groups")
            assert tool is not None
            result = await tool.fn()

            assert "groups" in result
            assert result["groups"] == mock_groups
            assert result["total"] == 2
            assert result["page"] == 1
            assert result["page_size"] == 100

    @pytest.mark.asyncio
    async def test_list_ldap_groups_with_pagination(self, register_tools):
        """Test list_ldap_groups with pagination."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get_with_headers = AsyncMock(return_value=([], {"X-Total-Count": "50"}))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_ldap_groups")
            assert tool is not None
            result = await tool.fn(page=2, page_size=25)

            assert result["page"] == 2
            assert result["page_size"] == 25
            call_args = mock_client.get_with_headers.call_args
            assert call_args[1]["params"]["pageNumber"] == 2
            assert call_args[1]["params"]["pageSize"] == 25

    @pytest.mark.asyncio
    async def test_list_ldap_groups_error(self, register_tools):
        """Test list_ldap_groups error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("LDAP not configured")
            error.details = {"status": 400}
            mock_client.get_with_headers = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "list_ldap_groups")
            assert tool is not None
            result = await tool.fn()

            assert "error" in result
            assert "LDAP not configured" in str(result["error"])


class TestGetTeamLdapGroupsTool:
    """Tests for get_team_ldap_groups tool."""

    @pytest.mark.asyncio
    async def test_get_team_ldap_groups_success(self, register_tools):
        """Test getting LDAP groups for a team."""
        mock_mappings = [
            {
                "uuid": "mapping-1",
                "team": {"uuid": "team-1", "name": "Developers"},
                "dn": "cn=developers,ou=groups,dc=example,dc=com",
            }
        ]

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_mappings)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team_ldap_groups")
            assert tool is not None
            result = await tool.fn(team_uuid="team-1")

            assert "mappings" in result
            assert result["mappings"] == mock_mappings
            mock_client.get.assert_called_once_with("/ldap/team/team-1")

    @pytest.mark.asyncio
    async def test_get_team_ldap_groups_empty(self, register_tools):
        """Test getting LDAP groups when none are mapped."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=[])
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team_ldap_groups")
            assert tool is not None
            result = await tool.fn(team_uuid="team-2")

            assert "mappings" in result
            assert result["mappings"] == []

    @pytest.mark.asyncio
    async def test_get_team_ldap_groups_error(self, register_tools):
        """Test get_team_ldap_groups error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Team not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "get_team_ldap_groups")
            assert tool is not None
            result = await tool.fn(team_uuid="bad-uuid")

            assert "error" in result
            assert "Team not found" in str(result["error"])


class TestAddLdapMappingTool:
    """Tests for add_ldap_mapping tool."""

    @pytest.mark.asyncio
    async def test_add_ldap_mapping_success(self, register_tools):
        """Test adding an LDAP mapping."""
        mock_mapping = {
            "uuid": "new-mapping",
            "team": {"uuid": "team-1"},
            "dn": "cn=developers,ou=groups,dc=example,dc=com",
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_mapping)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_ldap_mapping")
            assert tool is not None
            result = await tool.fn(
                team_uuid="team-1", dn="cn=developers,ou=groups,dc=example,dc=com"
            )

            assert "mapping" in result
            assert "message" in result
            assert "successfully" in result["message"].lower()
            assert result["mapping"] == mock_mapping

    @pytest.mark.asyncio
    async def test_add_ldap_mapping_payload(self, register_tools):
        """Test add_ldap_mapping sends correct payload."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_ldap_mapping")
            assert tool is not None
            await tool.fn(team_uuid="team-1", dn="cn=test,dc=example,dc=com")

            call_args = mock_client.put.call_args
            payload = call_args[1]["data"]
            assert payload["team"] == "team-1"
            assert payload["dn"] == "cn=test,dc=example,dc=com"

    @pytest.mark.asyncio
    async def test_add_ldap_mapping_error(self, register_tools):
        """Test add_ldap_mapping error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("LDAP group not found")
            error.details = {"status": 404}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "add_ldap_mapping")
            assert tool is not None
            result = await tool.fn(team_uuid="team-1", dn="cn=invalid,dc=example,dc=com")

            assert "error" in result
            assert "LDAP group not found" in str(result["error"])


class TestRemoveLdapMappingTool:
    """Tests for remove_ldap_mapping tool."""

    @pytest.mark.asyncio
    async def test_remove_ldap_mapping_success(self, register_tools):
        """Test removing an LDAP mapping."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.delete = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_ldap_mapping")
            assert tool is not None
            result = await tool.fn(mapping_uuid="mapping-123")

            assert "message" in result
            assert "removed" in result["message"].lower()
            assert "mapping-123" in result["message"]
            mock_client.delete.assert_called_once_with("/ldap/mapping/mapping-123")

    @pytest.mark.asyncio
    async def test_remove_ldap_mapping_error(self, register_tools):
        """Test remove_ldap_mapping error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Mapping not found")
            error.details = {"status": 404}
            mock_client.delete = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "remove_ldap_mapping")
            assert tool is not None
            result = await tool.fn(mapping_uuid="bad-uuid")

            assert "error" in result
            assert "Mapping not found" in str(result["error"])
