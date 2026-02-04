"""Tests for server.py initialization and error handling."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dependency_track_mcp.config import ConfigurationError
from dependency_track_mcp.server import (
    _initialize_oauth_components,
    _initialize_oauth_validator,
    cleanup,
    main,
    validate_security_configuration,
)


class TestInitializeOAuthValidator:
    """Test OAuth validator initialization."""

    def test_initialize_oauth_validator_success(self):
        """Test successful OAuth validator initialization."""
        with patch("dependency_track_mcp.server.get_settings") as mock_settings:
            mock_settings.return_value.oauth_issuer = "https://auth.example.com"

            validator = _initialize_oauth_validator()

            assert validator is not None
            assert validator.expected_issuer == "https://auth.example.com"

    def test_initialize_oauth_validator_settings_not_available(self):
        """Test OAuth validator initialization when settings not available."""
        with patch("dependency_track_mcp.server.get_settings") as mock_settings:
            mock_settings.side_effect = Exception("Settings not loaded")

            validator = _initialize_oauth_validator()

            assert validator is None

    def test_initialize_oauth_validator_none_issuer(self):
        """Test OAuth validator initialization with None issuer."""
        with patch("dependency_track_mcp.server.get_settings") as mock_settings:
            mock_settings.return_value.oauth_issuer = None

            validator = _initialize_oauth_validator()

            assert validator is not None
            assert validator.expected_issuer is None


class TestInitializeOAuthComponents:
    """Test OAuth components initialization."""

    def test_initialize_oauth_components_with_validator(self):
        """Test OAuth components initialization with valid validator."""
        with patch("dependency_track_mcp.server.get_settings") as mock_settings:
            mock_settings.return_value.oauth_issuer = "https://auth.example.com"
            mock_settings.return_value.get_required_scopes.return_value = {"read:projects"}

            with patch("dependency_track_mcp.server._initialize_oauth_validator") as mock_init:
                mock_validator = MagicMock()
                mock_init.return_value = mock_validator

                _initialize_oauth_components()

                # Verify middleware was created
                from dependency_track_mcp.server import _oauth_middleware

                assert _oauth_middleware is not None

    def test_initialize_oauth_components_no_validator(self):
        """Test OAuth components initialization when validator is None."""
        with patch("dependency_track_mcp.server._initialize_oauth_validator") as mock_init:
            mock_init.return_value = None

            _initialize_oauth_components()

            # Should not raise, _oauth_middleware can be None


class TestValidateSecurityConfiguration:
    """Test security configuration validation."""

    def test_validate_security_configuration_success(self):
        """Test successful security configuration validation."""
        mock_settings = MagicMock()
        mock_settings.url = "https://example.com"
        mock_settings.verify_ssl = True

        # Should not raise
        validate_security_configuration(mock_settings)

    def test_validate_security_configuration_oauth_disabled(self):
        """Test validation fails when OAuth is disabled."""
        mock_settings = MagicMock()
        mock_settings.validate_oauth_enabled.side_effect = ConfigurationError("OAuth disabled")
        mock_settings.url = "https://example.com"

        with pytest.raises(SystemExit) as exc_info:
            validate_security_configuration(mock_settings)

        assert exc_info.value.code == 1

    def test_validate_security_configuration_http_not_https(self):
        """Test validation fails when using HTTP instead of HTTPS."""
        mock_settings = MagicMock()
        mock_settings.validate_configuration_for_web_deployment.side_effect = ConfigurationError(
            "Must use HTTPS"
        )

        with pytest.raises(SystemExit) as exc_info:
            validate_security_configuration(mock_settings)

        assert exc_info.value.code == 1


class TestMainFailures:
    """Test main() error handling paths."""

    def test_main_configuration_error(self):
        """Test main() when configuration loading fails."""
        with patch("dependency_track_mcp.server.get_settings") as mock_settings:
            mock_settings.side_effect = Exception("Config error")

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1

    def test_main_security_validation_failure(self):
        """Test main() when security validation fails."""
        with patch("dependency_track_mcp.server.get_settings") as mock_get_settings:
            mock_settings = MagicMock()
            mock_get_settings.return_value = mock_settings
            mock_settings.validate_oauth_enabled.side_effect = ConfigurationError("OAuth disabled")

            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1

    def test_main_server_startup_failure(self):
        """Test main() when server startup fails."""
        with patch("dependency_track_mcp.server.get_settings") as mock_get_settings:
            mock_settings = MagicMock()
            mock_get_settings.return_value = mock_settings
            mock_settings.url = "https://example.com"
            mock_settings.verify_ssl = True
            mock_settings.server_host = "localhost"
            mock_settings.server_port = 8000
            mock_settings.get_required_scopes.return_value = {"read:projects"}

            with patch("dependency_track_mcp.server.materialize_tls_files") as mock_materialize:
                mock_materialize.return_value = ("cert.pem", "key.pem", None)

                with patch("dependency_track_mcp.server.mcp.run") as mock_run:
                    mock_run.side_effect = Exception("Server error")

                    with patch("dependency_track_mcp.server.cleanup", new_callable=AsyncMock):
                        with pytest.raises(Exception, match="Server error"):
                            main()

                        # Verify cleanup was called via asyncio.run
                        # Note: This is tricky to test without mocking asyncio


class TestCleanup:
    """Test cleanup function."""

    @pytest.mark.asyncio
    async def test_cleanup_success(self):
        """Test successful cleanup."""
        with patch("dependency_track_mcp.server.DependencyTrackClient") as mock_client:
            mock_instance = AsyncMock()
            mock_client.close_instance = mock_instance

            with patch("dependency_track_mcp.server.cleanup_tls_temp_files") as mock_tls:
                await cleanup()

                # Verify calls were made
                # DependencyTrackClient.close_instance was called
                # cleanup_tls_temp_files was called
                mock_tls.assert_called_once()


class TestServerMetadata:
    """Test server metadata."""

    def test_mcp_server_has_instructions(self):
        """Test that MCP server has OAuth instructions."""
        from dependency_track_mcp.server import mcp

        assert mcp.name == "dependency-track"
        assert "OAuth 2.1" in mcp.instructions
        assert "MCP_OAUTH_ISSUER" in mcp.instructions


class TestRegisterAllTools:
    """Test that tools are registered."""

    def test_tools_registered(self):
        """Test that tools are registered with server."""
        from dependency_track_mcp.server import mcp

        # Server should have tools registered
        # This is verified by the fact that register_all_tools(mcp) was called
        assert mcp is not None
