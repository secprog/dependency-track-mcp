"""Tests for configuration management."""

import os
import pytest
from pydantic import ValidationError

from dependency_track_mcp.config import Settings, get_settings


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
