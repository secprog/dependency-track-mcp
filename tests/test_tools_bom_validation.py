"""
Tests for BOM validation edge cases.
Targets base64 encoding line in validate_bom.
"""

import base64
from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.client import DependencyTrackClient
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.tools.bom import register_bom_tools
from tests.utils import find_tool


@pytest.fixture
def register_tools(mcp):
    """Register BOM tools."""
    register_bom_tools(mcp)
    return mcp


class TestBOMValidation:
    """Tests for BOM validation."""

    @pytest.mark.asyncio
    async def test_validate_bom_success(self, register_tools):
        """Test validating a valid BOM."""
        bom_content = '{"bomFormat": "CycloneDX", "specVersion": "1.4"}'

        validation_response = {
            "valid": True,
            "validationErrors": [],
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=validation_response)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "validate_bom")
            assert tool is not None
            result = await tool.fn(bom=bom_content)

            assert result["valid"] is True
            assert result["validationErrors"] == []

            # Verify base64 encoding was done correctly
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]

            # Decode and verify the BOM was encoded correctly
            encoded_bom = posted_data["bom"]
            decoded_bom = base64.b64decode(encoded_bom).decode("utf-8")
            assert decoded_bom == bom_content

    @pytest.mark.asyncio
    async def test_validate_bom_with_errors(self, register_tools):
        """Test validating an invalid BOM with errors."""
        bom_content = '{"invalid": "content"}'

        validation_response = {
            "valid": False,
            "validationErrors": ["Missing required field: bomFormat"],
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=validation_response)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "validate_bom")
            assert tool is not None
            result = await tool.fn(bom=bom_content)

            assert result["valid"] is False
            assert len(result["validationErrors"]) > 0

            # Verify base64 encoding line was executed
            call_args = mock_client.post.call_args
            assert call_args is not None
            posted_data = call_args[1]["data"]
            assert "bom" in posted_data

            # Verify we can decode it
            decoded_bom = base64.b64decode(posted_data["bom"]).decode("utf-8")
            assert decoded_bom == bom_content

    @pytest.mark.asyncio
    async def test_validate_bom_empty_content(self, register_tools):
        """Test validating with empty BOM content."""
        tool = find_tool(register_tools, "validate_bom")
        assert tool is not None
        result = await tool.fn(bom="")

        assert "error" in result
        assert result["error"] == "BOM content is required"

    @pytest.mark.asyncio
    async def test_validate_bom_unicode_content(self, register_tools):
        """Test validating BOM with unicode content."""
        # BOM with unicode characters
        bom_content = '{"bomFormat": "CycloneDX", "description": "Test with émojis 🚀"}'

        validation_response = {
            "valid": True,
            "validationErrors": [],
        }

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=validation_response)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "validate_bom")
            assert tool is not None
            result = await tool.fn(bom=bom_content)

            assert result["valid"] is True

            # Verify unicode was preserved through base64 encoding/decoding
            call_args = mock_client.post.call_args
            posted_data = call_args[1]["data"]
            decoded_bom = base64.b64decode(posted_data["bom"]).decode("utf-8")
            assert decoded_bom == bom_content
            assert "émojis 🚀" in decoded_bom

    @pytest.mark.asyncio
    async def test_validate_bom_error_handling(self, register_tools):
        """Test validate_bom error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Server error")
            error.details = {"status": 500}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "validate_bom")
            assert tool is not None
            result = await tool.fn(bom='{"test": "bom"}')

            assert "error" in result
            assert result["error"] == "Server error"
