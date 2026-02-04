"""Tests for VEX tools."""

import base64
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


class TestUploadVexTool:
    """Tests for upload_vex tool."""

    @pytest.mark.asyncio
    async def test_upload_vex_success(self, register_tools):
        """Test uploading a VEX document using PUT."""
        vex_content = '<?xml version="1.0"?><bom></bom>'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"token": "processing-token"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_vex")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid", vex=vex_content)

            assert "token" in result
            assert result["token"] == "processing-token"
            assert "message" in result
            assert "successfully" in result["message"].lower()
            mock_client.put.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_vex_encoding(self, register_tools):
        """Test upload_vex base64 encodes the VEX content."""
        vex_content = '<?xml version="1.0"?><bom></bom>'
        expected_encoding = base64.b64encode(vex_content.encode("utf-8")).decode("utf-8")

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value={"token": "token-123"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_vex")
            assert tool is not None
            await tool.fn(project_uuid="proj-uuid", vex=vex_content)

            call_args = mock_client.put.call_args
            assert call_args[1]["data"]["vex"] == expected_encoding
            assert call_args[1]["data"]["project"] == "proj-uuid"

    @pytest.mark.asyncio
    async def test_upload_vex_null_response(self, register_tools):
        """Test upload_vex with null response."""
        vex_content = '<?xml version="1.0"?><bom></bom>'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=None)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_vex")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid", vex=vex_content)

            assert result["token"] is None
            assert "message" in result

    @pytest.mark.asyncio
    async def test_upload_vex_error(self, register_tools):
        """Test upload_vex error handling."""
        vex_content = '<?xml version="1.0"?><bom></bom>'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Invalid VEX document")
            error.details = {"status": 400}
            mock_client.put = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_vex")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid", vex=vex_content)

            assert "error" in result
            assert "details" in result


class TestUploadVexPostTool:
    """Tests for upload_vex_post tool."""

    @pytest.mark.asyncio
    async def test_upload_vex_post_success(self, register_tools):
        """Test uploading a VEX document using POST."""
        vex_content = '<?xml version="1.0"?><bom></bom>'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={"token": "processing-token"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_vex_post")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid", vex=vex_content)

            assert "token" in result
            assert result["token"] == "processing-token"
            assert "message" in result
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_vex_post_encoding(self, register_tools):
        """Test upload_vex_post base64 encodes the VEX content."""
        vex_content = '<?xml version="1.0"?><bom></bom>'
        expected_encoding = base64.b64encode(vex_content.encode("utf-8")).decode("utf-8")

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value={"token": "token-456"})
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_vex_post")
            assert tool is not None
            await tool.fn(project_uuid="proj-uuid", vex=vex_content)

            call_args = mock_client.post.call_args
            assert call_args[1]["data"]["vex"] == expected_encoding
            assert call_args[1]["data"]["project"] == "proj-uuid"

    @pytest.mark.asyncio
    async def test_upload_vex_post_error(self, register_tools):
        """Test upload_vex_post error handling."""
        vex_content = '<?xml version="1.0"?><bom></bom>'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Project not found")
            error.details = {"status": 404}
            mock_client.post = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_vex_post")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid", vex=vex_content)

            assert "error" in result
            assert "details" in result


class TestExportProjectVexTool:
    """Tests for export_project_vex tool."""

    @pytest.mark.asyncio
    async def test_export_project_vex_success(self, register_tools):
        """Test exporting a project's VEX document."""
        vex_content = '<?xml version="1.0"?><bom></bom>'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=vex_content)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "export_project_vex")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid")

            assert "vex" in result
            assert result["vex"] == vex_content
            mock_client.get.assert_called_once_with("/vex/cyclonedx/project/proj-uuid")

    @pytest.mark.asyncio
    async def test_export_project_vex_error(self, register_tools):
        """Test export_project_vex error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            error = DependencyTrackError("Project not found")
            error.details = {"status": 404}
            mock_client.get = AsyncMock(side_effect=error)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "export_project_vex")
            assert tool is not None
            result = await tool.fn(project_uuid="bad-uuid")

            assert "error" in result
            assert "details" in result

    @pytest.mark.asyncio
    async def test_export_project_vex_empty_response(self, register_tools):
        """Test export_project_vex with empty response."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value="")
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "export_project_vex")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-uuid")

            assert "vex" in result
            assert result["vex"] == ""
