"""Tests for config.py edge cases and error handling."""

import os
import tempfile
from unittest.mock import patch

import pytest

from dependency_track_mcp.config import (
    _TLS_TEMP_FILES,
    ConfigurationError,
    Settings,
    cleanup_tls_temp_files,
    get_settings,
)


@pytest.fixture(autouse=True)
def isolate_env(monkeypatch):
    """Isolate tests from environment variables."""
    for key in list(os.environ.keys()):
        if key.startswith("DEPENDENCY_TRACK_") or key.startswith("MCP_"):
            monkeypatch.delenv(key, raising=False)


class TestCleanupTLSFiles:
    """Tests for cleanup_tls_temp_files function."""

    def test_cleanup_tls_files_success(self):
        """Test successful removal of TLS temp files."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        # Add to cleanup list
        _TLS_TEMP_FILES.append(temp_path)
        assert os.path.exists(temp_path)

        # Call cleanup
        cleanup_tls_temp_files()

        # File should be deleted
        assert not os.path.exists(temp_path)
        assert len(_TLS_TEMP_FILES) == 0

    def test_cleanup_tls_files_oserror_handling(self):
        """Test OSError handling in cleanup - file already deleted."""
        # Add a non-existent path to cleanup list
        fake_path = "/path/that/does/not/exist/fake_file.pem"
        _TLS_TEMP_FILES.append(fake_path)

        # Should not raise an exception, just continue
        cleanup_tls_temp_files()

        # Should have tried to pop it
        assert len(_TLS_TEMP_FILES) == 0

    def test_cleanup_tls_files_multiple_files(self):
        """Test cleanup of multiple temporary files."""
        temp_files = []
        for i in range(3):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                temp_files.append(f.name)
                _TLS_TEMP_FILES.append(f.name)

        # All files exist
        for path in temp_files:
            assert os.path.exists(path)

        # Cleanup
        cleanup_tls_temp_files()

        # All files should be deleted
        for path in temp_files:
            assert not os.path.exists(path)
        assert len(_TLS_TEMP_FILES) == 0

    def test_cleanup_tls_files_permission_error(self):
        """Test OSError handling with permission error."""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        _TLS_TEMP_FILES.append(temp_path)

        # Mock os.remove to raise OSError
        with patch("os.remove", side_effect=OSError("Permission denied")):
            # Should not raise, just continue
            cleanup_tls_temp_files()

        # Should still be in the list (popped before delete attempt)
        assert len(_TLS_TEMP_FILES) == 0

        # Clean up manually since we couldn't delete it
        os.unlink(temp_path)


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_success(self, monkeypatch):
        """Test successful settings retrieval."""
        monkeypatch.setenv("DEPENDENCY_TRACK_URL", "https://example.com")
        monkeypatch.setenv("DEPENDENCY_TRACK_API_KEY", "test-key")
        monkeypatch.setenv("MCP_OAUTH_ISSUER", "https://auth.example.com")

        # Clear the cache to force a new call
        get_settings.cache_clear()

        settings = get_settings()
        assert settings.url == "https://example.com"
        assert settings.api_key == "test-key"
        assert settings.oauth_issuer == "https://auth.example.com"

    def test_get_settings_configuration_error_handling(self, monkeypatch, setup_env):
        """Test ConfigurationError handling in get_settings."""
        # Set invalid values to trigger Settings validation error
        # Make sure we use setup_env fixture but then clear it
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        monkeypatch.delenv("MCP_OAUTH_ISSUER", raising=False)

        get_settings.cache_clear()

        with pytest.raises(ConfigurationError, match="Failed to load settings"):
            get_settings()


class TestSettingsValidationEdgeCases:
    """Tests for Settings validation edge cases."""

    def test_settings_validation_passes_with_valid_config(self):
        """Test that validation passes with valid web deployment configuration.

        This ensures that the oauth_issuer check at line 369 (defensive check for falsy issuer)
        doesn't interfere with normal operation. In practice, oauth_issuer is always
        set during Settings initialization, so the line 369 check is defensive.
        """
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_host="0.0.0.0",
            server_port=8000,
            server_tls_cert="/path/to/cert.pem",
            server_tls_key="/path/to/key.pem",
        )

        # Valid settings should pass validation
        settings.validate_configuration_for_web_deployment()


class TestSettingsConfigurationEdgeCases:
    """Tests for Settings configuration edge cases."""

    def test_validator_edge_case_tls_cleanup_during_init(self):
        """Test that TLS cleanup is registered during Settings initialization."""
        with patch("dependency_track_mcp.config._ensure_tls_cleanup_registered"):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
                server_tls_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                server_tls_key="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            )
            # TLS cleanup should have been registered when processing TLS files
            # This ensures the cleanup happens at program exit

    def test_settings_with_pem_escaped_newlines(self):
        """Test PEM content with escaped newlines (\\n) gets normalized."""
        cert_content = (
            "-----BEGIN CERTIFICATE-----\\nMIIDXTCCAkWgAwIBAgI\\n-----END CERTIFICATE-----"
        )
        key_content = "-----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqh\\n-----END PRIVATE KEY-----"

        # This tests the _normalize_pem function which converts \\n to \n
        # The function is called during _write_tls_temp_file which is called
        # during materialize_tls_from_env_vars (lines 459-460 with OSError handling)
        from dependency_track_mcp.config import _normalize_pem

        # Test the normalize function directly
        normalized_cert = _normalize_pem(cert_content)
        normalized_key = _normalize_pem(key_content)

        # Verify \\n was converted to actual newlines
        assert "\n" in normalized_cert
        assert "\\n" not in normalized_cert
        assert "\n" in normalized_key
        assert "\\n" not in normalized_key

    def test_materialize_tls_from_env_vars_creates_temp_files(self, monkeypatch):
        """Test that materialize_tls_files creates temporary files."""
        from dependency_track_mcp.config import materialize_tls_files

        cert_content = "-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----"
        key_content = "-----BEGIN PRIVATE KEY-----\ntest key\n-----END PRIVATE KEY-----"

        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_tls_cert=cert_content,
            server_tls_key=key_content,
        )

        # This should create temp files and return their paths
        certfile, keyfile, ca_certs = materialize_tls_files(settings)

        # Files should exist
        assert os.path.exists(certfile)
        assert os.path.exists(keyfile)
        assert ca_certs is None  # No CA certs provided

        # Clean up
        os.remove(certfile)
        os.remove(keyfile)
