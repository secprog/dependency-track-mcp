"""Test for oauth.py JWKS HTTP error handling (lines 172-183)."""

from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from dependency_track_mcp.oauth import (
    InvalidTokenError,
    JWTValidator,
)


class TestFetchJWKSHTTPErrors:
    """Test JWKS fetching with HTTP errors."""

    @pytest.mark.asyncio
    async def test_fetch_jwks_http_error_timeout(self):
        """Test JWKS fetch with HTTP timeout."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.side_effect = httpx.TimeoutException("Timeout")

            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidTokenError, match="Failed to fetch JWKS"):
                await validator.fetch_jwks()

    @pytest.mark.asyncio
    async def test_fetch_jwks_http_error_status(self):
        """Test JWKS fetch with HTTP error status."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_response = Mock()
            # raise_for_status is NOT async, it's a regular method
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                message="404 Not Found",
                request=Mock(),
                response=Mock(),
            )

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response

            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidTokenError, match="Failed to fetch JWKS"):
                await validator.fetch_jwks()

    @pytest.mark.asyncio
    async def test_fetch_jwks_http_error_connect_error(self):
        """Test JWKS fetch with connection error."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.side_effect = httpx.ConnectError("Connection refused")

            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidTokenError, match="Failed to fetch JWKS"):
                await validator.fetch_jwks()

    @pytest.mark.asyncio
    async def test_fetch_jwks_http_error_generic(self):
        """Test JWKS fetch with generic exception."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.side_effect = RuntimeError("Some unexpected error")

            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidTokenError, match="Failed to fetch JWKS"):
                await validator.fetch_jwks()

    @pytest.mark.asyncio
    async def test_fetch_jwks_http_error_json_decode(self):
        """Test JWKS fetch when response JSON is invalid."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_response = Mock()
            # raise_for_status is NOT async
            mock_response.raise_for_status.return_value = None
            # json() is NOT async for httpx responses
            mock_response.json.side_effect = ValueError("Invalid JSON")

            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response

            mock_client_cls.return_value = mock_client

            with pytest.raises(InvalidTokenError, match="Failed to fetch JWKS"):
                await validator.fetch_jwks()
