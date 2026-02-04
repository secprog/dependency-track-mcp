"""Tests for the HTTP client module."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dependency_track_mcp.client import DependencyTrackClient
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


class TestDependencyTrackClient:
    """Tests for DependencyTrackClient."""

    @pytest.fixture
    def settings(self):
        """Create test settings."""
        return Settings(
            url="https://localhost:8081",  # Changed to HTTPS
            api_key="test-key-123",
            oauth_issuer="https://auth.example.com",  # Added OAuth issuer
        )

    @pytest.fixture
    def client(self, settings):
        """Create test client."""
        return DependencyTrackClient(settings)

    def test_client_initialization(self, settings):
        """Test client initialization."""
        client = DependencyTrackClient(settings)
        assert client.settings == settings
        assert client._client is None

    def test_get_instance_singleton(self, settings, monkeypatch):
        """Test get_instance returns singleton."""
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        DependencyTrackClient._instance = None  # Reset singleton

        client1 = DependencyTrackClient.get_instance(settings)
        client2 = DependencyTrackClient.get_instance(settings)

        assert client1 is client2

    @pytest.mark.asyncio
    async def test_close_instance(self, settings, monkeypatch):
        """Test close_instance closes the singleton."""
        monkeypatch.delenv("DEPENDENCY_TRACK_URL", raising=False)
        monkeypatch.delenv("DEPENDENCY_TRACK_API_KEY", raising=False)
        DependencyTrackClient._instance = None

        DependencyTrackClient.get_instance(settings)
        await DependencyTrackClient.close_instance()

        assert DependencyTrackClient._instance is None

    @pytest.mark.asyncio
    async def test_get_success(self, client):
        """Test successful GET request."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.json.return_value = {"id": 1, "name": "Test"}

        with patch.object(client, "_request_with_retry", return_value=mock_response):
            result = await client.get("/test")
            assert result == {"id": 1, "name": "Test"}

    @pytest.mark.asyncio
    async def test_get_with_headers_success(self, client):
        """Test successful GET with headers."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.json.return_value = [{"id": 1}]
        mock_response.headers = {"x-total-count": "1"}

        with patch.object(client, "_request_with_retry", return_value=mock_response):
            data, headers = await client.get_with_headers("/test")
            assert data == [{"id": 1}]
            assert headers["x-total-count"] == "1"

    @pytest.mark.asyncio
    async def test_post_success(self, client):
        """Test successful POST request."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 2, "created": True}

        with patch.object(client, "_request_with_retry", return_value=mock_response):
            result = await client.post("/test", {"name": "New"})
            assert result["id"] == 2

    @pytest.mark.asyncio
    async def test_put_success(self, client):
        """Test successful PUT request."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 1, "updated": True}

        with patch.object(client, "_request_with_retry", return_value=mock_response):
            result = await client.put("/test/1", {"name": "Updated"})
            assert result["updated"] is True

    @pytest.mark.asyncio
    async def test_patch_success(self, client):
        """Test successful PATCH request."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 1, "patched": True}

        with patch.object(client, "_request_with_retry", return_value=mock_response):
            result = await client.patch("/test/1", {"status": "active"})
            assert result["patched"] is True

    @pytest.mark.asyncio
    async def test_delete_success(self, client):
        """Test successful DELETE request."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True
        mock_response.json.return_value = {}

        with patch.object(client, "_request_with_retry", return_value=mock_response):
            result = await client.delete("/test/1")
            assert result is None

    @pytest.mark.asyncio
    async def test_close_client(self, client):
        """Test closing the client."""
        # Create a mock client
        mock_async_client = AsyncMock(spec=httpx.AsyncClient)
        mock_async_client.is_closed = False
        client._client = mock_async_client

        await client.close()

        mock_async_client.aclose.assert_called_once()

    def test_handle_error_400_validation(self, client):
        """Test 400 error raises ValidationError."""
        response = MagicMock()
        response.status_code = 400
        response.json.return_value = {"error": "Bad request"}

        with pytest.raises(ValidationError):
            client._handle_error_response(response)

    def test_handle_error_401_authentication(self, client):
        """Test 401 error raises AuthenticationError."""
        response = MagicMock()
        response.status_code = 401
        response.json.return_value = {"error": "Unauthorized"}

        with pytest.raises(AuthenticationError):
            client._handle_error_response(response)

    def test_handle_error_403_authorization(self, client):
        """Test 403 error raises AuthorizationError."""
        response = MagicMock()
        response.status_code = 403
        response.json.return_value = {"error": "Forbidden"}

        with pytest.raises(AuthorizationError):
            client._handle_error_response(response)

    def test_handle_error_404_not_found(self, client):
        """Test 404 error raises NotFoundError."""
        response = MagicMock()
        response.status_code = 404
        response.json.return_value = {"error": "Not found"}

        with pytest.raises(NotFoundError):
            client._handle_error_response(response)

    def test_handle_error_409_conflict(self, client):
        """Test 409 error raises ConflictError."""
        response = MagicMock()
        response.status_code = 409
        response.json.return_value = {"error": "Conflict"}

        with pytest.raises(ConflictError):
            client._handle_error_response(response)

    def test_handle_error_429_rate_limit(self, client):
        """Test 429 error raises RateLimitError."""
        response = MagicMock()
        response.status_code = 429
        response.headers = {"Retry-After": "60"}
        response.json.return_value = {"error": "Too many requests"}

        with pytest.raises(RateLimitError) as exc_info:
            client._handle_error_response(response)

        assert exc_info.value.retry_after == 60

    def test_handle_error_429_no_retry_after(self, client):
        """Test 429 error without Retry-After header."""
        response = MagicMock()
        response.status_code = 429
        response.headers = {}
        response.json.return_value = {"error": "Too many requests"}

        with pytest.raises(RateLimitError) as exc_info:
            client._handle_error_response(response)

        assert exc_info.value.retry_after is None

    def test_handle_error_500_server_error(self, client):
        """Test 500+ error raises ServerError."""
        response = MagicMock()
        response.status_code = 500
        response.json.return_value = {"error": "Internal server error"}

        with pytest.raises(ServerError):
            client._handle_error_response(response)

    def test_handle_error_405_method_not_allowed(self, client):
        """Test 405 error raises ValidationError."""
        response = MagicMock()
        response.status_code = 405
        response.json.return_value = {"error": "Method not allowed"}

        with pytest.raises(ValidationError):
            client._handle_error_response(response)

    @pytest.mark.asyncio
    async def test_request_with_retry_success(self, client):
        """Test retry logic with immediate success."""
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.is_success = True

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.request.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = await client._request_with_retry("GET", "/test")

            assert result == mock_response
            mock_client.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_request_with_retry_connection_error(self, client):
        """Test retry on connection error."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.request.side_effect = httpx.ConnectError("Connection failed")
            mock_client_class.return_value = mock_client

            with pytest.raises(ConnectionError):
                await client._request_with_retry("GET", "/test")

    @pytest.mark.asyncio
    async def test_request_with_retry_timeout(self, client):
        """Test retry on timeout."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.request.side_effect = httpx.TimeoutException("Timeout")
            mock_client_class.return_value = mock_client

            with pytest.raises(ConnectionError):
                await client._request_with_retry("GET", "/test")

    @pytest.mark.asyncio
    async def test_request_with_retry_500_error(self, client):
        """Test retry on 500 error."""
        mock_response_500 = MagicMock()
        mock_response_500.is_success = False
        mock_response_500.status_code = 500
        mock_response_500.json.return_value = {"error": "Server error"}

        mock_response_200 = MagicMock()
        mock_response_200.is_success = True

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.request.side_effect = [mock_response_500, mock_response_200]
            mock_client_class.return_value = mock_client

            result = await client._request_with_retry("GET", "/test")

            assert result == mock_response_200
            assert mock_client.request.call_count == 2
