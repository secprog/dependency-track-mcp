"""Tests for event and task processing tools."""

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


class TestCheckEventTokenTool:
    """Tests for check_event_token tool."""

    @pytest.mark.asyncio
    async def test_check_event_token_processing(self, register_tools):
        """Test checking an event token that is still processing."""
        mock_event = {
            "token": "event-token-123",
            "processing": True,
            "percentComplete": 45,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_event)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "check_event_token")
            assert tool is not None
            result = await tool.fn(token="event-token-123")

            assert "event" in result
            assert result["event"] == mock_event
            mock_client.get.assert_called_once_with("/event/token/event-token-123")

    @pytest.mark.asyncio
    async def test_check_event_token_completed(self, register_tools):
        """Test checking an event token that has completed."""
        mock_event = {
            "token": "event-token-456",
            "processing": False,
            "percentComplete": 100,
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_event)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "check_event_token")
            assert tool is not None
            result = await tool.fn(token="event-token-456")

            assert "event" in result
            assert result["event"]["processing"] is False
            assert result["event"]["percentComplete"] == 100

    @pytest.mark.asyncio
    async def test_check_event_token_not_found(self, register_tools):
        """Test checking an event token that doesn't exist."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Event not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "check_event_token")
            assert tool is not None
            result = await tool.fn(token="invalid-token")

            assert "error" in result
            assert "Event not found" in str(result["error"])

    @pytest.mark.asyncio
    async def test_check_event_token_server_error(self, register_tools):
        """Test check_event_token with server error."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Internal server error")
            error.details = {"status": 500}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "check_event_token")
            assert tool is not None
            result = await tool.fn(token="event-token-789")

            assert "error" in result
            assert "Internal server error" in str(result["error"])

    @pytest.mark.asyncio
    async def test_check_event_token_different_formats(self, register_tools):
        """Test check_event_token with different token formats."""
        test_tokens = [
            "simple-token",
            "token-with-uuid-123e4567-e89b-12d3-a456-426614174000",
            "TOKEN_UPPERCASE",
        ]

        for token in test_tokens:
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value={"token": token, "processing": False})
                mock_get_instance.return_value = mock_client

                tool = find_tool(register_tools, "check_event_token")
                assert tool is not None
                result = await tool.fn(token=token)

                assert "event" in result
                assert result["event"]["token"] == token
