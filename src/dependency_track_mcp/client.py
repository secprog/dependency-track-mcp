"""Async HTTP client for Dependency Track API.

Security Features:
- HTTPS/TLS with certificate verification (verify_ssl setting)
- API key transmitted via secure X-Api-Key header
- No token passthrough (uses server's own API key)
- Exponential backoff for rate limiting
- Sanitized error messages (no credential leakage)
- Input/output validation via Pydantic models
"""

import asyncio
from typing import Any

import httpx

from dependency_track_mcp.config import Settings, get_settings
from dependency_track_mcp.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    ConnectionError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)


class DependencyTrackClient:
    """Async HTTP client for Dependency Track API with retry support."""

    _instance: "DependencyTrackClient | None" = None
    _client: httpx.AsyncClient | None = None

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self._client = None

    @classmethod
    def get_instance(cls, settings: Settings | None = None) -> "DependencyTrackClient":
        """Get or create singleton client instance."""
        if cls._instance is None:
            cls._instance = cls(settings)
        return cls._instance

    @classmethod
    async def close_instance(cls) -> None:
        """Close the singleton client instance."""
        if cls._instance is not None:
            await cls._instance.close()
            cls._instance = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client.
        
        Security: Client is configured with:
        - HTTPS base URL
        - X-Api-Key header for authentication (not exposed in logs)
        - TLS certificate verification (configurable via verify_ssl)
        - Request timeouts to prevent hanging
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.settings.api_base_url,
                headers={
                    "X-Api-Key": self.settings.api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=httpx.Timeout(self.settings.timeout),
                verify=self.settings.verify_ssl,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _handle_error_response(self, response: httpx.Response) -> None:
        """Convert HTTP error responses to appropriate exceptions.
        
        Security: Error messages are sanitized to prevent information disclosure.
        API keys and authentication headers are never included in error output.
        """
        status = response.status_code
        try:
            detail = response.json()
        except Exception:
            detail = {"message": response.text}

        message = detail.get("message", f"HTTP {status} error")

        if status == 400:
            raise ValidationError(message, details=detail)
        elif status == 401:
            raise AuthenticationError(
                "Authentication failed. Check your DEPENDENCY_TRACK_API_KEY.",
                details=detail,
            )
        elif status == 403:
            raise AuthorizationError(
                f"Permission denied: {message}. The API key may lack required permissions.",
                details=detail,
            )
        elif status == 404:
            raise NotFoundError(message, details=detail)
        elif status == 409:
            raise ConflictError(message, details=detail)
        elif status == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                "Rate limit exceeded. Please try again later.",
                retry_after=int(retry_after) if retry_after else None,
            )
        elif status >= 500:
            raise ServerError(f"Server error: {message}", details=detail)
        else:
            # Handle any other error status
            raise ValidationError(f"HTTP {status}: {message}", details=detail)

    async def _request_with_retry(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> httpx.Response:
        """Make a request with retry logic for transient failures."""
        client = await self._get_client()
        retries = 0
        last_exception = None

        while retries <= self.settings.max_retries:
            try:
                response = await client.request(method, endpoint, **kwargs)

                # Success
                if response.is_success:
                    return response

                # Retryable errors (429, 5xx)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After", "1")
                    wait_time = int(retry_after)
                    if retries < self.settings.max_retries:
                        await asyncio.sleep(wait_time)
                        retries += 1
                        continue
                    self._handle_error_response(response)
                elif response.status_code >= 500:
                    wait_time = 2**retries  # Exponential backoff
                    if retries < self.settings.max_retries:
                        await asyncio.sleep(wait_time)
                        retries += 1
                        continue
                    self._handle_error_response(response)
                elif 400 <= response.status_code < 500:
                    # All 4xx errors are non-retryable
                    self._handle_error_response(response)
                else:
                    # Handle any other error status
                    self._handle_error_response(response)

            except httpx.ConnectError as e:
                last_exception = ConnectionError(
                    f"Failed to connect to Dependency Track at {self.settings.url}: {e}"
                )
                if retries < self.settings.max_retries:
                    await asyncio.sleep(2**retries)
                    retries += 1
                    continue
                break

            except httpx.TimeoutException as e:
                last_exception = ConnectionError(f"Request timed out: {e}")
                if retries < self.settings.max_retries:
                    await asyncio.sleep(2**retries)
                    retries += 1
                    continue
                break

        raise last_exception or ServerError("Max retries exceeded")

    async def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Make a GET request."""
        response = await self._request_with_retry("GET", endpoint, params=params)
        return response.json()

    async def get_with_headers(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | list[Any], dict[str, str]]:
        """Make a GET request and return both body and headers."""
        response = await self._request_with_retry("GET", endpoint, params=params)
        return response.json(), dict(response.headers)

    async def post(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Make a POST request."""
        response = await self._request_with_retry(
            "POST", endpoint, json=data, params=params
        )
        if response.status_code == 204:
            return None
        return response.json()

    async def put(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Make a PUT request."""
        response = await self._request_with_retry(
            "PUT", endpoint, json=data, params=params
        )
        if response.status_code == 204:
            return None
        return response.json()

    async def patch(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Make a PATCH request."""
        response = await self._request_with_retry("PATCH", endpoint, json=data)
        if response.status_code == 204:
            return None
        return response.json()

    async def delete(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        """Make a DELETE request."""
        await self._request_with_retry("DELETE", endpoint, params=params)


# Convenience function for getting the client
def get_client() -> DependencyTrackClient:
    """Get the Dependency Track client instance."""
    return DependencyTrackClient.get_instance()
