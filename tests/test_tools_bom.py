"""Tests for BOM (Software Bill of Materials) tools."""

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


class TestUploadBomTool:
    """Tests for upload_bom tool."""

    @pytest.mark.asyncio
    async def test_upload_bom_with_project_uuid(self, register_tools):
        """Test uploading BOM with existing project."""
        mock_data = {"token": "token-123"}
        bom_content = '{"bomFormat": "CycloneDX"}'
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "upload_bom")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                bom=bom_content,
            )
            
            assert result["token"] == "token-123"

    @pytest.mark.asyncio
    async def test_upload_bom_with_auto_create(self, register_tools):
        """Test uploading BOM with auto-create."""
        mock_data = {"token": "token-123"}
        bom_content = '{"bomFormat": "CycloneDX"}'
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "upload_bom")
            assert tool is not None
            result = await tool.fn(
                project_name="New Project",
                project_version="1.0.0",
                bom=bom_content,
                auto_create=True,
            )
            
            assert result["token"] == "token-123"

    @pytest.mark.asyncio
    async def test_upload_bom_error(self, register_tools):
        """Test upload_bom error handling."""
        bom_content = '{"bomFormat": "CycloneDX"}'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.put = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_bom")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", bom=bom_content)

            assert "error" in result

    @pytest.mark.asyncio
    async def test_upload_bom_missing_parameters(self, register_tools):
        """Test uploading BOM without required parameters."""
        tool = find_tool(register_tools, "upload_bom")
        assert tool is not None
        result = await tool.fn()
        
        assert "error" in result

    @pytest.mark.asyncio
    async def test_upload_bom_missing_content(self, register_tools):
        """Test uploading BOM without content."""
        tool = find_tool(register_tools, "upload_bom")
        assert tool is not None
        result = await tool.fn(project_uuid="proj-1", bom="")

        assert "error" in result


class TestCheckBomProcessingTool:
    """Tests for check_bom_processing tool."""

    @pytest.mark.asyncio
    async def test_check_bom_processing_complete(self, register_tools):
        """Test checking BOM processing status."""
        mock_data = {"processing": False}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "check_bom_processing")
            assert tool is not None
            result = await tool.fn(token="token-123")
            
            assert result["processing"] is False

    @pytest.mark.asyncio
    async def test_check_bom_processing_in_progress(self, register_tools):
        """Test BOM processing in progress message."""
        mock_data = {"processing": True}

        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "check_bom_processing")
            assert tool is not None
            result = await tool.fn(token="token-123")

            assert result["processing"] is True

    @pytest.mark.asyncio
    async def test_check_bom_processing_error(self, register_tools):
        """Test check_bom_processing error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "check_bom_processing")
            assert tool is not None
            result = await tool.fn(token="token-123")

            assert "error" in result


class TestExportProjectBomTool:
    """Tests for export_project_bom tool."""

    @pytest.mark.asyncio
    async def test_export_project_bom_success(self, register_tools):
        """Test exporting project BOM."""
        mock_data = {"bomFormat": "CycloneDX", "version": 1}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "export_project_bom")
            assert tool is not None
            result = await tool.fn(
                project_uuid="proj-1",
                format="json",
                variant="withVulnerabilities",
            )
            
            assert "bom" in result

    @pytest.mark.asyncio
    async def test_export_project_bom_error(self, register_tools):
        """Test export_project_bom error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "export_project_bom")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", format="xml", variant="vex")

            assert "error" in result


class TestExportComponentBomTool:
    """Tests for export_component_bom tool."""

    @pytest.mark.asyncio
    async def test_export_component_bom_success(self, register_tools):
        """Test exporting component BOM."""
        mock_data = {"bomFormat": "CycloneDX", "component": {"name": "lodash"}}
        
        with patch.object(
            DependencyTrackClient, "get_instance"
        ) as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client
            
            tool = find_tool(register_tools, "export_component_bom")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")
            
            assert "bom" in result

    @pytest.mark.asyncio
    async def test_export_component_bom_error(self, register_tools):
        """Test export_component_bom error handling."""
        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "export_component_bom")
            assert tool is not None
            result = await tool.fn(component_uuid="comp-1")

            assert "error" in result


class TestUploadBomPostTool:
    """Tests for upload_bom_post tool."""

    @pytest.mark.asyncio
    async def test_upload_bom_post_success(self, register_tools):
        """Test uploading BOM using POST method."""
        mock_data = {"token": "token-456"}
        bom_content = '{"bomFormat": "CycloneDX"}'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_data)
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_bom_post")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", bom=bom_content)

            assert result["token"] == "token-456"

    @pytest.mark.asyncio
    async def test_upload_bom_post_error(self, register_tools):
        """Test upload_bom_post error handling."""
        bom_content = '{"bomFormat": "CycloneDX"}'

        with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
            mock_get_instance.return_value = mock_client

            tool = find_tool(register_tools, "upload_bom_post")
            assert tool is not None
            result = await tool.fn(project_uuid="proj-1", bom=bom_content)

            assert "error" in result


        @pytest.mark.asyncio
        async def test_upload_bom_post_missing_project_uuid_and_auto_create_params(self, register_tools):
            """Test upload_bom_post fails when neither project_uuid nor (auto_create + project_name) is provided."""
            bom_content = '{"bomFormat": "CycloneDX", "specVersion": "1.3", "components": []}'
        
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "upload_bom_post")
                assert tool is not None
                # Missing both project_uuid and (auto_create + project_name)
                result = await tool.fn(bom=bom_content)
            
                assert "error" in result
                assert "Either project_uuid or (auto_create with project_name) is required" in result["error"]
                # Ensure no API call was made
                mock_client.post.assert_not_called()

        @pytest.mark.asyncio
        async def test_upload_bom_post_missing_bom_content(self, register_tools):
            """Test upload_bom_post fails when BOM content is missing."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "upload_bom_post")
                assert tool is not None
                # Missing BOM content
                result = await tool.fn(project_uuid="proj-1", bom="")
            
                assert "error" in result
                assert "BOM content is required" in result["error"]
                # Ensure no API call was made
                mock_client.post.assert_not_called()

        @pytest.mark.asyncio
        async def test_upload_bom_post_with_auto_create_and_project_name(self, register_tools):
            """Test upload_bom_post with auto_create and project_name instead of project_uuid."""
            bom_content = '{"bomFormat": "CycloneDX", "specVersion": "1.3", "components": []}'
            mock_response = {
                "token": "upload-token-123",
            }
        
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "upload_bom_post")
                assert tool is not None
                result = await tool.fn(
                    bom=bom_content,
                    auto_create=True,
                    project_name="NewProject",
                    project_version="1.0.0"
                )
            
                assert "token" in result
            
                # Verify payload was constructed correctly
                call_args = mock_client.post.call_args
                payload = call_args[1]["data"]
                assert "bom" in payload
                assert payload["autoCreate"] is True
                assert payload["projectName"] == "NewProject"
                assert payload["projectVersion"] == "1.0.0"

                result = await tool.fn(bom=bom_content)
        
                assert "error" in result
                assert "Either project_uuid or (auto_create with project_name) is required" in result["error"]
                # Ensure no API call was made
                mock_client.post.assert_not_called()

        @pytest.mark.asyncio
        async def test_upload_bom_post_missing_bom_content(self, register_tools):
            """Test upload_bom_post fails when BOM content is missing."""
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_get_instance.return_value = mock_client
        
                tool = find_tool(register_tools, "upload_bom_post")
                assert tool is not None
                # Missing BOM content
                result = await tool.fn(project_uuid="proj-1", bom="")
        
                assert "error" in result
                assert "BOM content is required" in result["error"]
                # Ensure no API call was made
                mock_client.post.assert_not_called()

        @pytest.mark.asyncio
        async def test_upload_bom_post_with_auto_create_and_project_name(self, register_tools):
            """Test upload_bom_post with auto_create and project_name instead of project_uuid."""
            bom_content = '{"bomFormat": "CycloneDX", "specVersion": "1.3", "components": []}'
            mock_response = {
                "token": "upload-token-123",
            }
        
            with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_get_instance.return_value = mock_client
            
                tool = find_tool(register_tools, "upload_bom_post")
                assert tool is not None
                result = await tool.fn(
                    bom=bom_content,
                    auto_create=True,
                    project_name="NewProject",
                    project_version="1.0.0"
                )
            
                assert "token" in result
            
                # Verify payload was constructed correctly
                call_args = mock_client.post.call_args
                payload = call_args[1]["data"]
                assert "bom" in payload
                assert payload["autoCreate"] is True
                assert payload["projectName"] == "NewProject"
                assert payload["projectVersion"] == "1.0.0"

# TODO: Implement validate_bom tool in bom.py before enabling these tests
# class TestValidateBomTool:
#     """Tests for validate_bom tool."""
#
#     @pytest.mark.asyncio
#     async def test_validate_bom_valid(self, register_tools):
#         """Test validating valid BOM."""
#         mock_data = {"valid": True, "validationErrors": []}
#         bom_content = '{"bomFormat": "CycloneDX"}'
#         
#         with patch.object(
#             DependencyTrackClient, "get_instance"
#         ) as mock_get_instance:
#             mock_client = AsyncMock()
#             mock_client.post = AsyncMock(return_value=mock_data)
#             mock_get_instance.return_value = mock_client
#             
#             tool = find_tool(register_tools, "validate_bom")
#             assert tool is not None
#             result = await tool.fn(bom=bom_content)
#             
#             assert result["valid"] is True
#             assert result["validationErrors"] == []
#
#     @pytest.mark.asyncio
#     async def test_validate_bom_invalid(self, register_tools):
#         """Test validating invalid BOM."""
#         mock_data = {
#             "valid": False,
#             "validationErrors": ["Missing required field: components"],
#         }
#         bom_content = "{}"
#         
#         with patch.object(
#             DependencyTrackClient, "get_instance"
#         ) as mock_get_instance:
#             mock_client = AsyncMock()
#             mock_client.post = AsyncMock(return_value=mock_data)
#             mock_get_instance.return_value = mock_client
#             
#             tool = find_tool(register_tools, "validate_bom")
#             assert tool is not None
#             result = await tool.fn(bom=bom_content)
#             
#             assert result["valid"] is False
#
#     @pytest.mark.asyncio
#     async def test_validate_bom_error(self, register_tools):
#         """Test validate_bom error handling."""
#         bom_content = "{}"
#
#         with patch.object(DependencyTrackClient, "get_instance") as mock_get_instance:
#             mock_client = AsyncMock()
#             mock_client.post = AsyncMock(side_effect=DependencyTrackError("Boom"))
#             mock_get_instance.return_value = mock_client
#
#             tool = find_tool(register_tools, "validate_bom")
#             assert tool is not None
#             result = await tool.fn(bom=bom_content)
#
#             assert "error" in result
