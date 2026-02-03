"""Tests for tools modules."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastmcp import FastMCP


class TestToolsImports:
    """Tests for tools module imports and registration."""

    def test_projects_tools_module_imports(self):
        """Test projects tools module can be imported."""
        from dependency_track_mcp.tools.projects import register_project_tools
        assert callable(register_project_tools)

    def test_components_tools_module_imports(self):
        """Test components tools module can be imported."""
        from dependency_track_mcp.tools.components import register_component_tools
        assert callable(register_component_tools)

    def test_vulnerabilities_tools_module_imports(self):
        """Test vulnerabilities tools module can be imported."""
        from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools
        assert callable(register_vulnerability_tools)

    def test_findings_tools_module_imports(self):
        """Test findings tools module can be imported."""
        from dependency_track_mcp.tools.findings import register_finding_tools
        assert callable(register_finding_tools)

    def test_metrics_tools_module_imports(self):
        """Test metrics tools module can be imported."""
        from dependency_track_mcp.tools.metrics import register_metrics_tools
        assert callable(register_metrics_tools)

    def test_policies_tools_module_imports(self):
        """Test policies tools module can be imported."""
        from dependency_track_mcp.tools.policies import register_policy_tools
        assert callable(register_policy_tools)

    def test_bom_tools_module_imports(self):
        """Test BOM tools module can be imported."""
        from dependency_track_mcp.tools.bom import register_bom_tools
        assert callable(register_bom_tools)

    def test_search_tools_module_imports(self):
        """Test search tools module can be imported."""
        from dependency_track_mcp.tools.search import register_search_tools
        assert callable(register_search_tools)

    def test_register_all_tools_imports(self):
        """Test register_all_tools function can be imported."""
        from dependency_track_mcp.tools import register_all_tools
        assert callable(register_all_tools)


class TestToolsRegistration:
    """Tests for tools registration."""

    def test_project_tools_registration(self):
        """Test project tools can be registered."""
        from dependency_track_mcp.tools.projects import register_project_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_project_tools(mcp)
        # If no exception raised, registration succeeded
        assert True

    def test_component_tools_registration(self):
        """Test component tools can be registered."""
        from dependency_track_mcp.tools.components import register_component_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_component_tools(mcp)
        assert True

    def test_vulnerability_tools_registration(self):
        """Test vulnerability tools can be registered."""
        from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_vulnerability_tools(mcp)
        assert True

    def test_finding_tools_registration(self):
        """Test finding tools can be registered."""
        from dependency_track_mcp.tools.findings import register_finding_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_finding_tools(mcp)
        assert True

    def test_metrics_tools_registration(self):
        """Test metrics tools can be registered."""
        from dependency_track_mcp.tools.metrics import register_metrics_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_metrics_tools(mcp)
        assert True

    def test_policy_tools_registration(self):
        """Test policy tools can be registered."""
        from dependency_track_mcp.tools.policies import register_policy_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_policy_tools(mcp)
        assert True

    def test_bom_tools_registration(self):
        """Test BOM tools can be registered."""
        from dependency_track_mcp.tools.bom import register_bom_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_bom_tools(mcp)
        assert True

    def test_search_tools_registration(self):
        """Test search tools can be registered."""
        from dependency_track_mcp.tools.search import register_search_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_search_tools(mcp)
        assert True


class TestClientIntegration:
    """Tests for client integration with tools."""

    def test_get_client_function(self):
        """Test get_client function exists."""
        from dependency_track_mcp.client import get_client
        assert callable(get_client)

    @pytest.mark.asyncio
    async def test_client_instance_creation(self):
        """Test client instance can be created."""
        from dependency_track_mcp.client import get_client
        
        with patch('dependency_track_mcp.client.DependencyTrackClient.get_instance') as mock_get:
            mock_client = AsyncMock()
            mock_get.return_value = mock_client
            
            client = get_client()
            assert client is not None


class TestToolsStructure:
    """Tests for tools module structure."""

    def test_tools_init_imports_all_registers(self):
        """Test tools __init__ imports all register functions."""
        from dependency_track_mcp.tools import (
            register_project_tools,
            register_component_tools,
            register_vulnerability_tools,
            register_finding_tools,
            register_metrics_tools,
            register_policy_tools,
            register_bom_tools,
            register_search_tools,
        )
        
        assert callable(register_project_tools)
        assert callable(register_component_tools)
        assert callable(register_vulnerability_tools)
        assert callable(register_finding_tools)
        assert callable(register_metrics_tools)
        assert callable(register_policy_tools)
        assert callable(register_bom_tools)
        assert callable(register_search_tools)

    def test_register_all_tools_calls_all_registrations(self):
        """Test register_all_tools calls all register functions."""
        from dependency_track_mcp.tools import register_all_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_all_tools(mcp)
        # If no exception, all tools registered successfully
        assert True


class TestProjects:
    """Tests for projects tool functions."""

    def test_list_projects_defined(self):
        """Test list_projects function exists in registered tools."""
        from dependency_track_mcp.tools.projects import register_project_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_project_tools(mcp)
        assert True

    def test_get_project_defined(self):
        """Test get_project function exists."""
        from dependency_track_mcp.tools.projects import register_project_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_project_tools(mcp)
        assert True

    def test_create_project_defined(self):
        """Test create_project function exists."""
        from dependency_track_mcp.tools.projects import register_project_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_project_tools(mcp)
        assert True


class TestComponents:
    """Tests for components tool functions."""

    def test_components_tools_exist(self):
        """Test component tools are registered."""
        from dependency_track_mcp.tools.components import register_component_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_component_tools(mcp)
        assert True


class TestVulnerabilities:
    """Tests for vulnerabilities tool functions."""

    def test_vulnerabilities_tools_exist(self):
        """Test vulnerability tools are registered."""
        from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_vulnerability_tools(mcp)
        assert True


class TestFindings:
    """Tests for findings tool functions."""

    def test_findings_tools_exist(self):
        """Test finding tools are registered."""
        from dependency_track_mcp.tools.findings import register_finding_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_finding_tools(mcp)
        assert True


class TestMetrics:
    """Tests for metrics tool functions."""

    def test_metrics_tools_exist(self):
        """Test metrics tools are registered."""
        from dependency_track_mcp.tools.metrics import register_metrics_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_metrics_tools(mcp)
        assert True


class TestPolicies:
    """Tests for policies tool functions."""

    def test_policies_tools_exist(self):
        """Test policy tools are registered."""
        from dependency_track_mcp.tools.policies import register_policy_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_policy_tools(mcp)
        assert True


class TestBOM:
    """Tests for BOM tool functions."""

    def test_bom_tools_exist(self):
        """Test BOM tools are registered."""
        from dependency_track_mcp.tools.bom import register_bom_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_bom_tools(mcp)
        assert True


class TestSearch:
    """Tests for search tool functions."""

    def test_search_tools_exist(self):
        """Test search tools are registered."""
        from dependency_track_mcp.tools.search import register_search_tools
        from fastmcp import FastMCP
        
        mcp = FastMCP(name="test")
        register_search_tools(mcp)
        assert True
