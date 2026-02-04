"""Tests for configuration management."""

import os
import pytest
from pydantic import ValidationError

from dependency_track_mcp.config import ConfigurationError, Settings, get_settings


@pytest.fixture(autouse=True)
def isolate_env(monkeypatch):
    """Isolate tests from environment variables and .env file."""
    # Clear any existing settings that might interfere
    for key in list(os.environ.keys()):
        if key.startswith("DEPENDENCY_TRACK_") or key.startswith("MCP_"):
            monkeypatch.delenv(key, raising=False)
    # Disable .env file loading by setting empty string
    monkeypatch.setenv("DEPENDENCY_TRACK_URL", "")
    monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)


class TestSettings:
    """Tests for Settings class."""

    def test_settings_creation_with_defaults(self):
        """Test creating Settings with default values."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
        )
        assert settings.url == "https://example.com"
        assert settings.api_key == "test-key"
        assert settings.oauth_issuer == "https://auth.example.com"
        assert settings.timeout == 30
        assert settings.verify_ssl is True
        assert settings.max_retries == 3

    def test_settings_url_validation_removes_trailing_slash(self):
        """Test that URL validator removes trailing slash."""
        settings = Settings(
            url="https://example.com/",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
        )
        assert settings.url == "https://example.com"

    def test_settings_multiple_trailing_slashes_removed(self):
        """Test that multiple trailing slashes are removed."""
        settings = Settings(
            url="https://example.com///",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
        )
        assert settings.url == "https://example.com"

    def test_settings_api_base_url(self):
        """Test api_base_url property."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
        )
        assert settings.api_base_url == "https://example.com/api/v1"

    def test_settings_api_base_url_with_stripped_slash(self):
        """Test api_base_url with stripped trailing slash."""
        settings = Settings(
            url="https://example.com/",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
        )
        assert settings.api_base_url == "https://example.com/api/v1"

    def test_settings_custom_timeout(self):
        """Test custom timeout value."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            timeout=60,
        )
        assert settings.timeout == 60

    def test_settings_timeout_validation_min(self):
        """Test timeout validation minimum value."""
        with pytest.raises(ValidationError):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
                timeout=0,  # Less than 1
            )

    def test_settings_timeout_validation_max(self):
        """Test timeout validation maximum value."""
        with pytest.raises(ValidationError):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
                timeout=301,  # Greater than 300
            )

    def test_settings_max_retries_validation(self):
        """Test max_retries validation."""
        with pytest.raises(ValidationError):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
                max_retries=11,  # Greater than 10
            )

    def test_settings_required_fields(self, monkeypatch):
        """Test that required fields are enforced."""
        # Clear env vars to test validation
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        monkeypatch.delenv("MCP_OAUTH_ISSUER", raising=False)
        with pytest.raises(ValidationError):
            Settings()  # type: ignore[call-arg]  # Missing url, api_key, and oauth_issuer

    def test_settings_missing_url(self, monkeypatch):
        """Test that url is required."""
        # Clear env vars to test validation
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        monkeypatch.delenv("MCP_OAUTH_ISSUER", raising=False)
        with pytest.raises(ValidationError):
            Settings(url=None, api_key="test-key", oauth_issuer="https://auth.example.com")  # type: ignore

    def test_settings_missing_api_key(self, monkeypatch):
        """Test that api_key is required."""
        # Clear env vars to test validation
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        monkeypatch.delenv("MCP_OAUTH_ISSUER", raising=False)
        with pytest.raises(ValidationError):
            Settings(url="https://example.com", api_key=None, oauth_issuer="https://auth.example.com")  # type: ignore

    def test_settings_missing_oauth_issuer(self, monkeypatch):
        """Test that oauth_issuer is required."""
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        monkeypatch.delenv("MCP_OAUTH_ISSUER", raising=False)
        with pytest.raises(ValidationError):
            Settings(url="https://example.com", api_key="test-key")  # type: ignore[call-arg]

    def test_get_settings_returns_singleton(self, monkeypatch):
        """Test that get_settings returns cached instance."""
        # Set up required env vars for get_settings
        monkeypatch.setenv("DEPENDENCY_TRACK_URL", "https://singleton.example.com")
        monkeypatch.setenv("DEPENDENCY_TRACK_API_KEY", "singleton-key")
        monkeypatch.setenv("MCP_OAUTH_ISSUER", "https://auth.example.com")
        # Clear cache
        get_settings.cache_clear()
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2
        # Clean up cache
        get_settings.cache_clear()

    def test_settings_verify_ssl_false(self):
        """Test verify_ssl can be set to False."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            verify_ssl=False,
        )
        assert settings.verify_ssl is False

    def test_settings_max_retries_zero(self):
        """Test max_retries can be 0."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            max_retries=0,
        )
        assert settings.max_retries == 0

    def test_settings_from_env(self, monkeypatch):
        """Test loading settings from environment variables."""
        monkeypatch.setenv("DEPENDENCY_TRACK_URL", "https://env.example.com")
        monkeypatch.setenv("DEPENDENCY_TRACK_API_KEY", "env-api-key")
        monkeypatch.setenv("DEPENDENCY_TRACK_TIMEOUT", "60")
        monkeypatch.setenv("DEPENDENCY_TRACK_VERIFY_SSL", "false")
        monkeypatch.setenv("DEPENDENCY_TRACK_MAX_RETRIES", "5")
        monkeypatch.setenv("MCP_OAUTH_ISSUER", "https://auth.example.com")

        settings = Settings(
            url="https://env.example.com",
            api_key="env-api-key",
            oauth_issuer="https://auth.example.com",
        )
        assert settings.url == "https://env.example.com"
        assert settings.api_key == "env-api-key"
        assert settings.timeout == 60
        assert settings.verify_ssl is False
        assert settings.max_retries == 5

    def test_settings_http_url_fails_without_dev_mode(self):
        """Test that HTTP URL fails without dev_allow_http."""
        with pytest.raises(ValidationError):
            Settings(
                url="http://example.com",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
            )

    def test_settings_http_url_succeeds_with_dev_mode(self):
        """Test that HTTP URL succeeds with dev_allow_http=True."""
        settings = Settings(
            url="http://localhost:8080",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            dev_allow_http=True,
        )
        assert settings.url == "http://localhost:8080"

    def test_settings_http_oauth_issuer_fails_without_dev_mode(self):
        """Test that HTTP OAuth issuer fails without dev_allow_http."""
        with pytest.raises(ValidationError):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="http://auth.example.com",
            )

    def test_settings_http_oauth_issuer_succeeds_with_dev_mode(self):
        """Test that HTTP OAuth issuer succeeds with dev_allow_http=True."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="http://localhost:9000",
            dev_allow_http=True,
        )
        assert settings.oauth_issuer == "http://localhost:9000"
    def test_settings_invalid_url_format(self):
        """Test that invalid URL format raises ValueError."""
        with pytest.raises(ValueError, match="must be a valid URL"):
            Settings(
                url="not-a-valid-url",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
            )

    def test_settings_invalid_oauth_issuer_format(self):
        """Test that invalid OAuth issuer format raises ValueError."""
        with pytest.raises(ValueError, match="must be a valid URL"):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="invalid-issuer",
            )

    def test_settings_oauth_issuer_non_https_scheme_fails(self):
        """Test that non-HTTP/HTTPS OAuth issuer scheme fails."""
        with pytest.raises(ValueError, match="must use HTTPS or HTTP scheme"):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="ftp://auth.example.com",
            )

    def test_settings_url_without_scheme_fails(self):
        """Test that URL without scheme fails."""
        with pytest.raises(ValueError, match="must be a valid URL"):
            Settings(
                url="example.com",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
            )

    def test_settings_oauth_jwks_url_auto_derived_keycloak(self):
        """Test that JWKS URL is auto-derived for Keycloak."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com/realms/myrealm",
        )
        assert settings.oauth_jwks_url == "https://auth.example.com/realms/myrealm/protocol/openid-connect/certs"

    def test_settings_oauth_jwks_url_auto_derived_generic(self):
        """Test that JWKS URL is auto-derived for generic OIDC."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
        )
        assert settings.oauth_jwks_url == "https://auth.example.com/.well-known/jwks.json"

    def test_settings_oauth_jwks_url_explicit(self):
        """Test that explicit JWKS URL is used."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            oauth_jwks_url="https://custom.example.com/jwks",
        )
        assert settings.oauth_jwks_url == "https://custom.example.com/jwks"

    def test_settings_oauth_disabled_raises_error(self):
        """Test that disabling OAuth raises ConfigurationError."""
        with pytest.raises(ConfigurationError, match="OAuth 2.1 authorization is MANDATORY"):
            settings = Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="https://auth.example.com",
                oauth_enabled=False,
            )
            settings.validate_oauth_enabled()

    def test_validate_configuration_for_web_deployment_http_url_fails(self):
        """Test that HTTP URL fails web deployment validation without dev mode."""
        settings = Settings(
            url="http://example.com",  # HTTP URL
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_host="0.0.0.0",
            server_port=8000,
            server_tls_cert="/path/to/cert.pem",
            server_tls_key="/path/to/key.pem",
            dev_allow_http=True,  # Need this to create the object
        )
        # Disable dev_allow_http to trigger the error
        settings.dev_allow_http = False
        with pytest.raises(ConfigurationError, match="must use HTTPS"):
            settings.validate_configuration_for_web_deployment()

    def test_validate_configuration_for_web_deployment_http_oauth_fails(self):
        """Test that HTTP OAuth issuer fails web deployment validation without dev mode."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="http://auth.example.com",  # HTTP issuer
            server_host="0.0.0.0",
            server_port=8000,
            server_tls_cert="/path/to/cert.pem",
            server_tls_key="/path/to/key.pem",
            dev_allow_http=True,  # Need this to create the object
        )
        # Disable dev_allow_http to trigger the error
        settings.dev_allow_http = False
        with pytest.raises(ConfigurationError, match="must use HTTPS"):
            settings.validate_configuration_for_web_deployment()

    def test_validate_configuration_for_web_deployment_no_tls_cert_fails(self):
        """Test that missing TLS cert fails web deployment validation."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_host="0.0.0.0",
            server_port=8000,
            server_tls_key="/path/to/key.pem",
        )
        with pytest.raises(ConfigurationError, match="TLS is required"):
            settings.validate_configuration_for_web_deployment()

    def test_validate_configuration_for_web_deployment_no_tls_key_fails(self):
        """Test that missing TLS key fails web deployment validation."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_host="0.0.0.0",
            server_port=8000,
            server_tls_cert="/path/to/cert.pem",
        )
        with pytest.raises(ConfigurationError, match="TLS is required"):
            settings.validate_configuration_for_web_deployment()

    def test_validate_configuration_for_web_deployment_verify_ssl_false_fails(self):
        """Test that SSL verification disabled fails web deployment validation."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_host="0.0.0.0",
            server_port=8000,
            server_tls_cert="/path/to/cert.pem",
            server_tls_key="/path/to/key.pem",
            verify_ssl=False,
        )
        with pytest.raises(ConfigurationError, match="SSL certificate verification must be enabled"):
            settings.validate_configuration_for_web_deployment()

    def test_validate_configuration_for_web_deployment_no_oauth_issuer_fails(self):
        """Test that missing OAuth issuer fails web deployment validation."""
        with pytest.raises(ValueError, match="OAUTH_ISSUER"):
            Settings(
                url="https://example.com",
                api_key="test-key",
                oauth_issuer="",  # Empty issuer should fail during initialization
                server_host="0.0.0.0",
                server_port=8000,
                server_tls_cert="/path/to/cert.pem",
                server_tls_key="/path/to/key.pem",
            )

    def test_validate_configuration_for_web_deployment_success(self):
        """Test successful web deployment validation."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            oauth_issuer="https://auth.example.com",
            server_host="0.0.0.0",
            server_port=8000,
            server_tls_cert="/path/to/cert.pem",
            server_tls_key="/path/to/key.pem",
        )
        # Should not raise
        settings.validate_configuration_for_web_deployment()


class TestTLSHelpers:
    """Test TLS helper functions."""

    def test_materialize_tls_files_success(self):
        """Test successful TLS file materialization."""
        from dependency_track_mcp.config import materialize_tls_files, cleanup_tls_temp_files
        
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
        from dependency_track_mcp.config import materialize_tls_files, cleanup_tls_temp_files
        
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
        from dependency_track_mcp.config import materialize_tls_files, cleanup_tls_temp_files
        
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
        from dependency_track_mcp.config import materialize_tls_files
        
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
        from dependency_track_mcp.config import materialize_tls_files
        
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
        from dependency_track_mcp.config import materialize_tls_files, cleanup_tls_temp_files
        
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

