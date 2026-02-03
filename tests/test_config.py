"""Tests for configuration management."""

import pytest
from pydantic import ValidationError

from dependency_track_mcp.config import Settings, get_settings


class TestSettings:
    """Tests for Settings class."""

    def test_settings_creation_with_defaults(self):
        """Test creating Settings with default values."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
        )
        assert settings.url == "https://example.com"
        assert settings.api_key == "test-key"
        assert settings.timeout == 30
        assert settings.verify_ssl is True
        assert settings.max_retries == 3

    def test_settings_url_validation_removes_trailing_slash(self):
        """Test that URL validator removes trailing slash."""
        settings = Settings(
            url="https://example.com/",
            api_key="test-key",
        )
        assert settings.url == "https://example.com"

    def test_settings_multiple_trailing_slashes_removed(self):
        """Test that multiple trailing slashes are removed."""
        settings = Settings(
            url="https://example.com///",
            api_key="test-key",
        )
        assert settings.url == "https://example.com"

    def test_settings_api_base_url(self):
        """Test api_base_url property."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
        )
        assert settings.api_base_url == "https://example.com/api/v1"

    def test_settings_api_base_url_with_stripped_slash(self):
        """Test api_base_url with stripped trailing slash."""
        settings = Settings(
            url="https://example.com/",
            api_key="test-key",
        )
        assert settings.api_base_url == "https://example.com/api/v1"

    def test_settings_custom_timeout(self):
        """Test custom timeout value."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            timeout=60,
        )
        assert settings.timeout == 60

    def test_settings_timeout_validation_min(self):
        """Test timeout validation minimum value."""
        with pytest.raises(ValidationError):
            Settings(
                url="https://example.com",
                api_key="test-key",
                timeout=0,  # Less than 1
            )

    def test_settings_timeout_validation_max(self):
        """Test timeout validation maximum value."""
        with pytest.raises(ValidationError):
            Settings(
                url="https://example.com",
                api_key="test-key",
                timeout=301,  # Greater than 300
            )

    def test_settings_max_retries_validation(self):
        """Test max_retries validation."""
        with pytest.raises(ValidationError):
            Settings(
                url="https://example.com",
                api_key="test-key",
                max_retries=11,  # Greater than 10
            )

    def test_settings_required_fields(self, monkeypatch):
        """Test that required fields are enforced."""
        # Clear env vars to test validation
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            Settings()  # Missing url and api_key

    def test_settings_missing_url(self, monkeypatch):
        """Test that url is required."""
        # Clear env vars to test validation
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            Settings(api_key="test-key")

    def test_settings_missing_api_key(self, monkeypatch):
        """Test that api_key is required."""
        # Clear env vars to test validation
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        with pytest.raises(ValidationError):
            Settings(url="https://example.com")

    def test_get_settings_returns_singleton(self):
        """Test that get_settings returns cached instance."""
        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2

    def test_settings_verify_ssl_false(self):
        """Test verify_ssl can be set to False."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
            verify_ssl=False,
        )
        assert settings.verify_ssl is False

    def test_settings_max_retries_zero(self):
        """Test max_retries can be 0."""
        settings = Settings(
            url="https://example.com",
            api_key="test-key",
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

        settings = Settings()
        assert settings.url == "https://env.example.com"
        assert settings.api_key == "env-api-key"
        assert settings.timeout == 60
        assert settings.verify_ssl is False
        assert settings.max_retries == 5
