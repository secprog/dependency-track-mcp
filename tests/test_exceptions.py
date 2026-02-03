"""Tests for custom exceptions."""

import pytest

from dependency_track_mcp.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    ConnectionError,
    ConfigurationError,
    DependencyTrackError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)


class TestDependencyTrackError:
    """Tests for base DependencyTrackError."""

    def test_exception_message(self):
        """Test exception message."""
        error = DependencyTrackError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"

    def test_exception_with_details(self):
        """Test exception with details."""
        details = {"key": "value"}
        error = DependencyTrackError("Test error", details=details)
        assert error.details == details

    def test_exception_default_details(self):
        """Test exception with default empty details."""
        error = DependencyTrackError("Test error")
        assert error.details == {}

    def test_exception_inheritance(self):
        """Test that it inherits from Exception."""
        error = DependencyTrackError("Test error")
        assert isinstance(error, Exception)


class TestConfigurationError:
    """Tests for ConfigurationError."""

    def test_configuration_error(self):
        """Test ConfigurationError creation."""
        error = ConfigurationError("Missing config")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Missing config"


class TestAuthenticationError:
    """Tests for AuthenticationError."""

    def test_authentication_error(self):
        """Test AuthenticationError creation."""
        error = AuthenticationError("Invalid credentials")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Invalid credentials"


class TestAuthorizationError:
    """Tests for AuthorizationError."""

    def test_authorization_error(self):
        """Test AuthorizationError creation."""
        error = AuthorizationError("Permission denied")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Permission denied"


class TestNotFoundError:
    """Tests for NotFoundError."""

    def test_not_found_error(self):
        """Test NotFoundError creation."""
        error = NotFoundError("Resource not found")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Resource not found"


class TestValidationError:
    """Tests for ValidationError."""

    def test_validation_error(self):
        """Test ValidationError creation."""
        error = ValidationError("Invalid input")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Invalid input"


class TestConflictError:
    """Tests for ConflictError."""

    def test_conflict_error(self):
        """Test ConflictError creation."""
        error = ConflictError("Resource conflict")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Resource conflict"


class TestRateLimitError:
    """Tests for RateLimitError."""

    def test_rate_limit_error_without_retry_after(self):
        """Test RateLimitError without retry_after."""
        error = RateLimitError("Rate limit exceeded")
        assert isinstance(error, DependencyTrackError)
        assert error.retry_after is None

    def test_rate_limit_error_with_retry_after(self):
        """Test RateLimitError with retry_after."""
        error = RateLimitError("Rate limit exceeded", retry_after=60)
        assert error.retry_after == 60


class TestServerError:
    """Tests for ServerError."""

    def test_server_error(self):
        """Test ServerError creation."""
        error = ServerError("Internal server error")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Internal server error"


class TestConnectionError:
    """Tests for ConnectionError."""

    def test_connection_error(self):
        """Test ConnectionError creation."""
        error = ConnectionError("Connection failed")
        assert isinstance(error, DependencyTrackError)
        assert str(error) == "Connection failed"
