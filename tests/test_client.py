"""Tests for the Dependency Track HTTP client."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dependency_track_mcp.client import DependencyTrackClient, get_client
from dependency_track_mcp.config import Settings
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


class TestDependencyTrackClientInit:
    """Tests for DependencyTrackClient initialization."""

    def test_client_initialization_with_settings(self, settings):
        """Test initializing client with settings."""
        client = DependencyTrackClient(settings)
        assert client.settings == settings
        assert client._client is None

    def test_client_initialization_without_settings(self, mock_env_vars):
        """Test initializing client without settings (loads from env)."""
        client = DependencyTrackClient()
        assert client.settings is not None
        assert client.settings.url == "https://test.example.com"

    def test_get_instance_singleton(self, settings):
        """Test get_instance returns singleton."""
        instance1 = DependencyTrackClient.get_instance(settings)
        instance2 = DependencyTrackClient.get_instance()
        assert instance1 is instance2

    def test_get_client_convenience_function(self, settings):
        """Test get_client convenience function."""
        DependencyTrackClient.get_instance(settings)
        client = get_client()
        assert isinstance(client, DependencyTrackClient)


class TestClientHTTPMethods:
    """Tests for HTTP methods."""

    @pytest.mark.asyncio
    async def test_get_request(self, mock_client, mock_response):
        """Test GET request."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        result = await mock_client.get("/project")
        assert result == {"test": "data"}

    @pytest.mark.asyncio
    async def test_get_with_params(self, mock_client, mock_response):
        """Test GET request with parameters."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        result = await mock_client.get("/project", params={"name": "test"})
        assert result == {"test": "data"}

    @pytest.mark.asyncio
    async def test_get_with_headers(self, mock_client, mock_response):
        """Test GET request returning body and headers."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        result, headers = await mock_client.get_with_headers("/project")
        assert result == {"test": "data"}
        assert "X-Total-Count" in headers

    @pytest.mark.asyncio
    async def test_post_request(self, mock_client, mock_response):
        """Test POST request."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        result = await mock_client.post("/project", data={"name": "test"})
        assert result == {"test": "data"}

    @pytest.mark.asyncio
    async def test_post_request_204_response(self, mock_client):
        """Test POST request with 204 No Content response."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 204
        response.is_success = True
        mock_client._client.request = AsyncMock(return_value=response)
        result = await mock_client.post("/project", data={"name": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_put_request(self, mock_client, mock_response):
        """Test PUT request."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        result = await mock_client.put("/project", data={"name": "test"})
        assert result == {"test": "data"}

    @pytest.mark.asyncio
    async def test_put_request_204_response(self, mock_client):
        """Test PUT request with 204 No Content response."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 204
        response.is_success = True
        mock_client._client.request = AsyncMock(return_value=response)
        result = await mock_client.put("/project", data={"name": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_patch_request(self, mock_client, mock_response):
        """Test PATCH request."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        result = await mock_client.patch("/project", data={"name": "test"})
        assert result == {"test": "data"}

    @pytest.mark.asyncio
    async def test_patch_request_204_response(self, mock_client):
        """Test PATCH request with 204 No Content response."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 204
        response.is_success = True
        mock_client._client.request = AsyncMock(return_value=response)
        result = await mock_client.patch("/project", data={"name": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_request(self, mock_client, mock_response):
        """Test DELETE request."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        await mock_client.delete("/project/123")
        mock_client._client.request.assert_called_once()


class TestClientErrorHandling:
    """Tests for error handling."""

    def test_handle_error_400_validation_error(self, mock_client):
        """Test handling 400 Bad Request."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 400
        response.json.return_value = {"message": "Invalid request"}
        with pytest.raises(ValidationError):
            mock_client._handle_error_response(response)

    def test_handle_error_401_authentication_error(self, mock_client):
        """Test handling 401 Unauthorized."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 401
        response.json.return_value = {"message": "Invalid API key"}
        with pytest.raises(AuthenticationError):
            mock_client._handle_error_response(response)

    def test_handle_error_403_authorization_error(self, mock_client):
        """Test handling 403 Forbidden."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 403
        response.json.return_value = {"message": "Permission denied"}
        with pytest.raises(AuthorizationError):
            mock_client._handle_error_response(response)

    def test_handle_error_404_not_found_error(self, mock_client):
        """Test handling 404 Not Found."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 404
        response.json.return_value = {"message": "Not found"}
        with pytest.raises(NotFoundError):
            mock_client._handle_error_response(response)

    def test_handle_error_409_conflict_error(self, mock_client):
        """Test handling 409 Conflict."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 409
        response.json.return_value = {"message": "Conflict"}
        with pytest.raises(ConflictError):
            mock_client._handle_error_response(response)

    def test_handle_error_429_rate_limit_error(self, mock_client):
        """Test handling 429 Rate Limit."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 429
        response.headers = {"Retry-After": "60"}
        response.json.return_value = {"message": "Rate limited"}
        with pytest.raises(RateLimitError) as exc_info:
            mock_client._handle_error_response(response)
        assert exc_info.value.retry_after == 60

    def test_handle_error_500_server_error(self, mock_client):
        """Test handling 500 Internal Server Error."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 500
        response.json.return_value = {"message": "Server error"}
        with pytest.raises(ServerError):
            mock_client._handle_error_response(response)

    def test_handle_error_non_json_response(self, mock_client):
        """Test handling error with non-JSON response."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 400
        response.json.side_effect = Exception("Not JSON")
        response.text = "Error text"
        with pytest.raises(ValidationError):
            mock_client._handle_error_response(response)


class TestClientRetryLogic:
    """Tests for retry logic."""

    @pytest.mark.asyncio
    async def test_request_with_retry_success(self, mock_client, mock_response):
        """Test successful request with retry."""
        mock_client._client.request = AsyncMock(return_value=mock_response)
        result = await mock_client._request_with_retry("GET", "/project")
        assert result == mock_response

    @pytest.mark.asyncio
    async def test_request_with_retry_connection_error(self, mock_client):
        """Test retry on connection error."""
        mock_client._client.request = AsyncMock(
            side_effect=httpx.ConnectError("Connection failed")
        )
        with pytest.raises(ConnectionError):
            await mock_client._request_with_retry("GET", "/project")

    @pytest.mark.asyncio
    async def test_request_with_retry_timeout(self, mock_client):
        """Test retry on timeout."""
        mock_client._client.request = AsyncMock(
            side_effect=httpx.TimeoutException("Timeout")
        )
        with pytest.raises(ConnectionError):
            await mock_client._request_with_retry("GET", "/project")

    @pytest.mark.asyncio
    async def test_request_with_retry_rate_limit(self, mock_client):
        """Test retry logic on 429 rate limit."""
        response = MagicMock(spec=httpx.Response)
        response.status_code = 429
        response.is_success = False
        response.headers = {"Retry-After": "1"}
        response.json.return_value = {"message": "Rate limited"}
        mock_client._client.request = AsyncMock(return_value=response)

        with patch("dependency_track_mcp.client.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            with pytest.raises(RateLimitError):
                await mock_client._request_with_retry("GET", "/project")

        sleep_mock.assert_called()

    @pytest.mark.asyncio
    async def test_request_with_retry_rate_limit_then_success(self, settings):
        """Test 429 retry then success."""
        settings.max_retries = 1
        client = DependencyTrackClient(settings)
        client._client = AsyncMock(spec=httpx.AsyncClient)
        client._client.is_closed = False

        response_429 = MagicMock(spec=httpx.Response)
        response_429.status_code = 429
        response_429.is_success = False
        response_429.headers = {"Retry-After": "1"}
        response_429.json.return_value = {"message": "Rate limited"}

        response_ok = MagicMock(spec=httpx.Response)
        response_ok.status_code = 200
        response_ok.is_success = True
        response_ok.json.return_value = {"ok": True}

        client._client.request = AsyncMock(side_effect=[response_429, response_ok])

        with patch("dependency_track_mcp.client.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            result = await client._request_with_retry("GET", "/project")

        assert result is response_ok
        sleep_mock.assert_called()

    @pytest.mark.asyncio
    async def test_request_with_retry_connect_error_then_success(self, settings):
        """Test connection error then success."""
        settings.max_retries = 1
        client = DependencyTrackClient(settings)
        client._client = AsyncMock(spec=httpx.AsyncClient)
        client._client.is_closed = False

        response_ok = MagicMock(spec=httpx.Response)
        response_ok.status_code = 200
        response_ok.is_success = True
        response_ok.json.return_value = {"ok": True}

        client._client.request = AsyncMock(
            side_effect=[httpx.ConnectError("Connection failed"), response_ok]
        )

        with patch("dependency_track_mcp.client.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            result = await client._request_with_retry("GET", "/project")

        assert result is response_ok
        sleep_mock.assert_called()

    @pytest.mark.asyncio
    async def test_request_with_retry_server_error_no_retry(self, settings):
        """Test 500 error with max_retries=0 raises ServerError."""
        settings.max_retries = 0
        client = DependencyTrackClient(settings)
        client._client = AsyncMock(spec=httpx.AsyncClient)
        client._client.is_closed = False

        response = MagicMock(spec=httpx.Response)
        response.status_code = 500
        response.is_success = False
        response.headers = {}
        response.json.return_value = {"message": "Server error"}
        client._client.request = AsyncMock(return_value=response)

        with pytest.raises(ServerError):
            await client._request_with_retry("GET", "/project")

    @pytest.mark.asyncio
    async def test_request_with_retry_server_error_then_success(self, settings):
        """Test 500 error then success retries once."""
        settings.max_retries = 1
        client = DependencyTrackClient(settings)
        client._client = AsyncMock(spec=httpx.AsyncClient)
        client._client.is_closed = False

        response_500 = MagicMock(spec=httpx.Response)
        response_500.status_code = 500
        response_500.is_success = False
        response_500.headers = {}
        response_500.json.return_value = {"message": "Server error"}

        response_ok = MagicMock(spec=httpx.Response)
        response_ok.status_code = 200
        response_ok.is_success = True
        response_ok.json.return_value = {"ok": True}

        client._client.request = AsyncMock(side_effect=[response_500, response_ok])

        with patch("dependency_track_mcp.client.asyncio.sleep", new=AsyncMock()) as sleep_mock:
            result = await client._request_with_retry("GET", "/project")

        assert result is response_ok
        sleep_mock.assert_called()

    @pytest.mark.asyncio
    async def test_request_with_retry_client_error(self, settings):
        """Test 4xx response handling in retry loop."""
        settings.max_retries = 0
        client = DependencyTrackClient(settings)
        client._client = AsyncMock(spec=httpx.AsyncClient)
        client._client.is_closed = False

        response_404 = MagicMock(spec=httpx.Response)
        response_404.status_code = 404
        response_404.is_success = False
        response_404.headers = {}
        response_404.json.return_value = {"message": "Not found"}

        client._client.request = AsyncMock(return_value=response_404)

        with pytest.raises(NotFoundError):
            await client._request_with_retry("GET", "/project")

    @pytest.mark.asyncio
    async def test_request_with_retry_other_status(self, settings):
        """Test non-4xx/5xx response handling in retry loop."""
        settings.max_retries = 0
        client = DependencyTrackClient(settings)
        client._client = AsyncMock(spec=httpx.AsyncClient)
        client._client.is_closed = False

        response_302 = MagicMock(spec=httpx.Response)
        response_302.status_code = 302
        response_302.is_success = False
        response_302.headers = {}
        response_302.json.return_value = {"message": "Redirect"}

        client._client.request = AsyncMock(return_value=response_302)

        with pytest.raises(ValidationError):
            await client._request_with_retry("GET", "/project")

    @pytest.mark.asyncio
    async def test_request_with_retry_max_retries_exceeded(self, settings):
        """Test max retries exceeded path raises ConnectionError."""
        settings.max_retries = 0
        client = DependencyTrackClient(settings)
        client._client = AsyncMock(spec=httpx.AsyncClient)
        client._client.is_closed = False

        client._client.request = AsyncMock(side_effect=httpx.ConnectError("Connection failed"))

        with pytest.raises(ConnectionError):
            await client._request_with_retry("GET", "/project")


class TestClientLifecycle:
    """Tests for client lifecycle."""

    @pytest.mark.asyncio
    async def test_close_client(self, settings):
        """Test closing client."""
        client = DependencyTrackClient(settings)
        mock_async_client = AsyncMock(spec=httpx.AsyncClient)
        mock_async_client.is_closed = False
        client._client = mock_async_client
        await client.close()
        mock_async_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_singleton_instance(self, settings):
        """Test closing singleton instance."""
        DependencyTrackClient.get_instance(settings)
        await DependencyTrackClient.close_instance()
        assert DependencyTrackClient._instance is None
