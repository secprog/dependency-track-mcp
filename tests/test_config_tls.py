"""Additional tests for config TLS functions."""

import os

import pytest

from dependency_track_mcp.config import (
    ConfigurationError,
    Settings,
    cleanup_tls_temp_files,
    materialize_tls_files,
)


class TestTLSHelpers:
    """Test TLS helper functions."""

    def test_materialize_tls_files_success(self):
        """Test successful TLS file materialization."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_tls_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            server_tls_key="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
        )

        certfile, keyfile, ca_certs = materialize_tls_files(settings)

        try:
            assert os.path.exists(certfile)
            assert os.path.exists(keyfile)
            assert ca_certs is None

            # Verify content
            with open(certfile) as f:
                content = f.read()
                assert "BEGIN CERTIFICATE" in content
        finally:
            cleanup_tls_temp_files()

    def test_materialize_tls_files_with_ca_certs(self):
        """Test TLS file materialization with CA certs."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_tls_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            server_tls_key="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            server_tls_ca_certs="-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
        )

        certfile, keyfile, ca_certs = materialize_tls_files(settings)

        try:
            assert os.path.exists(certfile)
            assert os.path.exists(keyfile)
            assert ca_certs is not None
            assert os.path.exists(ca_certs)

            # Verify CA content
            with open(ca_certs) as f:
                content = f.read()
                assert "ca" in content
        finally:
            cleanup_tls_temp_files()

    def test_materialize_tls_files_normalized_newlines(self):
        """Test that \\n escapes are normalized."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_tls_cert="-----BEGIN CERTIFICATE-----\\ntest\\n-----END CERTIFICATE-----",
            server_tls_key="-----BEGIN PRIVATE KEY-----\\ntest\\n-----END PRIVATE KEY-----",
        )

        certfile, keyfile, ca_certs = materialize_tls_files(settings)

        try:
            # Verify newlines were properly normalized
            with open(certfile) as f:
                content = f.read()
                assert "\n" in content
                assert "\\n" not in content
        finally:
            cleanup_tls_temp_files()

    def test_materialize_tls_files_missing_cert_fails(self):
        """Test that missing cert fails."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_tls_key="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
        )

        with pytest.raises(ConfigurationError, match="TLS is required"):
            materialize_tls_files(settings)

    def test_materialize_tls_files_missing_key_fails(self):
        """Test that missing key fails."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_tls_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        )

        with pytest.raises(ConfigurationError, match="TLS is required"):
            materialize_tls_files(settings)

    def test_cleanup_tls_temp_files(self):
        """Test TLS temp file cleanup."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_tls_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            server_tls_key="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
        )

        certfile, keyfile, ca_certs = materialize_tls_files(settings)

        # Files should exist
        assert os.path.exists(certfile)
        assert os.path.exists(keyfile)

        # Cleanup
        cleanup_tls_temp_files()

        # Files should be removed
        assert not os.path.exists(certfile)
        assert not os.path.exists(keyfile)

    def test_get_required_scopes(self):
        """Test get_required_scopes property."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            oauth_required_scopes="read:projects write:projects read:vulnerabilities",
        )

        scopes = settings.get_required_scopes()
        assert scopes == {"read:projects", "write:projects", "read:vulnerabilities"}

    def test_oauth_resource_metadata_url(self, setup_env):
        """Test oauth_resource_metadata_url property."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            # Use the default oauth_resource_uri
        )

        metadata_url = settings.oauth_resource_metadata_url
        # Default oauth_resource_uri is "https://mcp.example.com/mcp"
        assert metadata_url == "https://mcp.example.com/.well-known/oauth-protected-resource"
