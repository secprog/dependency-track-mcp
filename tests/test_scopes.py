"""Tests for scopes module."""

from dependency_track_mcp.scopes import Scopes


class TestScopes:
    """Tests for scopes module."""

    def test_scopes_class_defined(self):
        """Test Scopes class is defined."""
        assert Scopes is not None

    def test_read_projects_scope(self):
        """Test READ_PROJECTS scope."""
        assert Scopes.READ_PROJECTS == "read:projects"

    def test_write_projects_scope(self):
        """Test WRITE_PROJECTS scope."""
        assert Scopes.WRITE_PROJECTS == "write:projects"

    def test_read_components_scope(self):
        """Test READ_COMPONENTS scope."""
        assert Scopes.READ_COMPONENTS == "read:components"

    def test_read_vulnerabilities_scope(self):
        """Test READ_VULNERABILITIES scope."""
        assert Scopes.READ_VULNERABILITIES == "read:vulnerabilities"

    def test_write_analysis_scope(self):
        """Test WRITE_ANALYSIS scope."""
        assert Scopes.WRITE_ANALYSIS == "write:analysis"

    def test_read_metrics_scope(self):
        """Test READ_METRICS scope."""
        assert Scopes.READ_METRICS == "read:metrics"

    def test_read_policies_scope(self):
        """Test READ_POLICIES scope."""
        assert Scopes.READ_POLICIES == "read:policies"

    def test_upload_bom_scope(self):
        """Test UPLOAD_BOM scope."""
        assert Scopes.UPLOAD_BOM == "upload:bom"

    def test_search_scope(self):
        """Test SEARCH scope."""
        assert Scopes.SEARCH == "search"

    def test_all_scopes_are_strings(self):
        """Test all scopes are strings."""
        scope_values = [
            Scopes.READ_PROJECTS,
            Scopes.WRITE_PROJECTS,
            Scopes.READ_COMPONENTS,
            Scopes.READ_VULNERABILITIES,
            Scopes.WRITE_ANALYSIS,
            Scopes.READ_METRICS,
            Scopes.READ_POLICIES,
            Scopes.UPLOAD_BOM,
            Scopes.SEARCH,
        ]
        for scope in scope_values:
            assert isinstance(scope, str)
            assert len(scope) > 0
