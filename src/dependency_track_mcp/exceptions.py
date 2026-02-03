"""Custom exceptions for Dependency Track MCP Server."""


class DependencyTrackError(Exception):
    """Base exception for Dependency Track errors."""

    def __init__(self, message: str, details: dict | None = None):
        self.message = message
        self.details = details or {}
        super().__init__(message)


class ConfigurationError(DependencyTrackError):
    """Raised when configuration is missing or invalid."""

    pass


class AuthenticationError(DependencyTrackError):
    """Raised when API authentication fails (401)."""

    pass


class AuthorizationError(DependencyTrackError):
    """Raised when the API key lacks required permissions (403)."""

    pass


class NotFoundError(DependencyTrackError):
    """Raised when a requested resource is not found (404)."""

    pass


class ValidationError(DependencyTrackError):
    """Raised when request validation fails (400)."""

    pass


class ConflictError(DependencyTrackError):
    """Raised when there's a resource conflict (409)."""

    pass


class RateLimitError(DependencyTrackError):
    """Raised when rate limit is exceeded (429)."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ServerError(DependencyTrackError):
    """Raised when the server returns an error (5xx)."""

    pass


class ConnectionError(DependencyTrackError):
    """Raised when connection to the server fails."""

    pass
