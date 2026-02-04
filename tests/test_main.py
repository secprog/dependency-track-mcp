"""Comprehensive tests for main.py - FastAPI OAuth MCP Server.

Tests cover:
- JWT middleware authentication
- JWKS fetching and caching
- Protected resource metadata endpoint
- Health check endpoint
- Admin JWKS refresh endpoint
- Server startup with various configurations
- Error handling and edge cases
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt
from jose.exceptions import JWTError

from dependency_track_mcp.config import ConfigurationError, Settings
from dependency_track_mcp.main import (
    JWTAuthMiddleware,
    app,
    get_jwks,
    main,
    refresh_jwks_cache,
    verify_jwt_token,
)


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def valid_jwt_token():
    """Generate a valid JWT token for testing."""
    payload = {
        "sub": "test-user",
        "aud": None,
        "iss": "https://auth.example.com",
        "exp": 9999999999,
        "iat": 1,
        "nbf": 1,
    }
    return jose_jwt.encode(payload, "secret", algorithm="HS256")


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    return Settings(
        url="https://example.com",
        api_key="test-key",
        oauth_issuer="https://auth.example.com",
        oauth_jwks_url="https://auth.example.com/.well-known/jwks.json",
        oauth_audience=None,
        oauth_resource_uri="https://mcp.example.com/mcp",
    )


class TestJWTAuthMiddleware:
    """Tests for JWT authentication middleware."""

    @pytest.mark.asyncio
    async def test_middleware_with_valid_bearer_token(self):
        """Test middleware allows request with valid Bearer token."""
        app_mock = AsyncMock()
        middleware = JWTAuthMiddleware(app_mock)

        scope = {
            "type": "http",
            "path": "/mcp/something",
            "headers": [(b"authorization", b"Bearer valid-token")],
        }
        receive = AsyncMock()
        send = AsyncMock()

        with patch("dependency_track_mcp.main.verify_jwt_token") as mock_verify:
            mock_verify.return_value = {"sub": "test-user"}

            await middleware(scope, receive, send)

            # Verify app was called (after passing auth)
            app_mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_middleware_missing_bearer_token(self):
        """Test middleware rejects request without Bearer token."""
        app_mock = AsyncMock()
        middleware = JWTAuthMiddleware(app_mock)

        scope = {
            "type": "http",
            "path": "/mcp/something",
            "headers": [],  # No authorization header
        }
        receive = AsyncMock()
        send = AsyncMock()

        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = MagicMock(
                oauth_resource_metadata_url="https://example.com/.well-known/oauth"
            )

            await middleware(scope, receive, send)

            # send should have been called with 401 response
            assert send.called

    @pytest.mark.asyncio
    async def test_middleware_invalid_bearer_format(self):
        """Test middleware rejects invalid Bearer format."""
        app_mock = AsyncMock()
        middleware = JWTAuthMiddleware(app_mock)

        scope = {
            "type": "http",
            "path": "/mcp/something",
            "headers": [(b"authorization", b"InvalidFormat token")],
        }
        receive = AsyncMock()
        send = AsyncMock()

        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = MagicMock(
                oauth_resource_metadata_url="https://example.com/.well-known/oauth"
            )

            await middleware(scope, receive, send)

            assert send.called

    @pytest.mark.asyncio
    async def test_middleware_invalid_token(self):
        """Test middleware rejects invalid token."""
        app_mock = AsyncMock()
        middleware = JWTAuthMiddleware(app_mock)

        scope = {
            "type": "http",
            "path": "/mcp/something",
            "headers": [(b"authorization", b"Bearer invalid-token")],
        }
        receive = AsyncMock()
        send = AsyncMock()

        with patch("dependency_track_mcp.main.verify_jwt_token") as mock_verify:
            mock_verify.return_value = None  # Invalid token

            with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
                mock_get_settings.return_value = MagicMock(
                    oauth_resource_metadata_url="https://example.com/.well-known/oauth"
                )

                await middleware(scope, receive, send)

                assert send.called

    @pytest.mark.asyncio
    async def test_middleware_jwt_validation_error(self):
        """Test middleware handles JWT validation exceptions."""
        app_mock = AsyncMock()
        middleware = JWTAuthMiddleware(app_mock)

        scope = {
            "type": "http",
            "path": "/mcp/something",
            "headers": [(b"authorization", b"Bearer token")],
        }
        receive = AsyncMock()
        send = AsyncMock()

        with patch("dependency_track_mcp.main.verify_jwt_token") as mock_verify:
            mock_verify.side_effect = Exception("JWT validation error")

            with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
                mock_get_settings.return_value = MagicMock(
                    oauth_resource_metadata_url="https://example.com/.well-known/oauth"
                )

                await middleware(scope, receive, send)

                assert send.called

    @pytest.mark.asyncio
    async def test_middleware_non_mcp_path(self):
        """Test middleware allows non-/mcp paths without auth."""
        app_mock = AsyncMock()
        middleware = JWTAuthMiddleware(app_mock)

        scope = {
            "type": "http",
            "path": "/health",  # Not /mcp path
            "headers": [],
        }
        receive = AsyncMock()
        send = AsyncMock()

        await middleware(scope, receive, send)

        # App should be called without auth check
        app_mock.assert_called_once_with(scope, receive, send)

    @pytest.mark.asyncio
    async def test_middleware_websocket_type(self):
        """Test middleware allows non-HTTP scopes."""
        app_mock = AsyncMock()
        middleware = JWTAuthMiddleware(app_mock)

        scope = {
            "type": "websocket",  # Not HTTP
            "path": "/mcp/something",
            "headers": [],
        }
        receive = AsyncMock()
        send = AsyncMock()

        await middleware(scope, receive, send)

        # App should be called without auth check
        app_mock.assert_called_once_with(scope, receive, send)


class TestGetJWKS:
    """Tests for JWKS fetching and caching."""

    @pytest.mark.asyncio
    async def test_get_jwks_success(self, mock_settings):
        """Test successful JWKS fetch."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            mock_response = MagicMock()
            mock_response.json.return_value = {"keys": [{"kid": "key1"}]}

            with patch("httpx.AsyncClient"):
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client.__aenter__.return_value = mock_client

                with patch("httpx.AsyncClient", return_value=mock_client):
                    import dependency_track_mcp.main

                    dependency_track_mcp.main._jwks_cache = None  # Clear cache

                    jwks = await get_jwks()

                    assert jwks == {"keys": [{"kid": "key1"}]}

    @pytest.mark.asyncio
    async def test_get_jwks_cached(self, mock_settings):
        """Test JWKS cache is used."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            import dependency_track_mcp.main

            dependency_track_mcp.main._jwks_cache = {"keys": [{"cached": True}]}

            jwks = await get_jwks()

            assert jwks == {"keys": [{"cached": True}]}

    @pytest.mark.asyncio
    async def test_get_jwks_http_error(self, mock_settings):
        """Test JWKS fetch handles HTTP errors."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            with patch("httpx.AsyncClient"):
                mock_client = AsyncMock()
                mock_response = MagicMock()
                mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                    "404", request=MagicMock(), response=MagicMock()
                )
                mock_client.get = AsyncMock(return_value=mock_response)
                mock_client.__aenter__.return_value = mock_client

                with patch("httpx.AsyncClient", return_value=mock_client):
                    import dependency_track_mcp.main

                    dependency_track_mcp.main._jwks_cache = None

                    with pytest.raises(httpx.HTTPStatusError):
                        await get_jwks()

    @pytest.mark.asyncio
    async def test_get_jwks_no_url_configured(self):
        """Test get_jwks raises error when JWKS URL not configured."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.oauth_jwks_url = None
            mock_get_settings.return_value = mock_settings

            import dependency_track_mcp.main

            dependency_track_mcp.main._jwks_cache = None

            with pytest.raises(ValueError, match="JWKS URL not configured"):
                await get_jwks()


class TestRefreshJWKSCache:
    """Tests for JWKS cache management."""

    def test_refresh_jwks_cache_clears(self):
        """Test refresh_jwks_cache clears the cache."""
        import dependency_track_mcp.main

        dependency_track_mcp.main._jwks_cache = {"keys": []}

        refresh_jwks_cache()

        assert dependency_track_mcp.main._jwks_cache is None


class TestVerifyJWTToken:
    """Tests for JWT token verification."""

    @pytest.mark.asyncio
    async def test_verify_jwt_token_valid(self, mock_settings):
        """Test JWT verification with valid token."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            with patch("dependency_track_mcp.main.get_jwks") as mock_get_jwks:
                mock_get_jwks.return_value = {"keys": []}

                with patch("jose.jwt.decode") as mock_decode:
                    mock_decode.return_value = {"sub": "user123"}

                    result = await verify_jwt_token("token")

                    assert result == {"sub": "user123"}

    @pytest.mark.asyncio
    async def test_verify_jwt_token_jwks_fetch_error(self, mock_settings):
        """Test JWT verification when JWKS fetch fails."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            with patch("dependency_track_mcp.main.get_jwks") as mock_get_jwks:
                mock_get_jwks.side_effect = Exception("Network error")

                result = await verify_jwt_token("token")

                assert result is None

    @pytest.mark.asyncio
    async def test_verify_jwt_token_invalid_signature(self, mock_settings):
        """Test JWT verification with invalid signature."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            with patch("dependency_track_mcp.main.get_jwks") as mock_get_jwks:
                mock_get_jwks.return_value = {"keys": []}

                with patch("jose.jwt.decode") as mock_decode:
                    mock_decode.side_effect = JWTError("Invalid signature")

                    result = await verify_jwt_token("token")

                    assert result is None

    @pytest.mark.asyncio
    async def test_verify_jwt_token_other_error(self, mock_settings):
        """Test JWT verification handles other exceptions."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            with patch("dependency_track_mcp.main.get_jwks") as mock_get_jwks:
                mock_get_jwks.return_value = {"keys": []}

                with patch("jose.jwt.decode") as mock_decode:
                    mock_decode.side_effect = Exception("Unexpected error")

                    result = await verify_jwt_token("token")

                    assert result is None


class TestProtectedResourceMetadata:
    """Tests for OAuth Protected Resource Metadata endpoint."""

    def test_protected_resource_metadata(self, client, mock_settings):
        """Test /.well-known/oauth-protected-resource endpoint."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            response = client.get("/.well-known/oauth-protected-resource")

            assert response.status_code == 200
            data = response.json()
            assert data["resource"] == mock_settings.oauth_resource_uri
            assert data["authorization_servers"] == [mock_settings.oauth_issuer]


class TestHealthCheck:
    """Tests for health check endpoint."""

    def test_health_check(self, client, mock_settings):
        """Test /health endpoint."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["mcp_integrated"] is True
            assert "jwks_cached" in data

    def test_health_check_jwks_cached(self, client, mock_settings):
        """Test health check reports JWKS cache state."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_get_settings.return_value = mock_settings

            import dependency_track_mcp.main

            dependency_track_mcp.main._jwks_cache = {"keys": []}

            try:
                response = client.get("/health")

                assert response.status_code == 200
                data = response.json()
                assert data["jwks_cached"] is True
            finally:
                dependency_track_mcp.main._jwks_cache = None


class TestAdminRefreshJWKS:
    """Tests for admin JWKS refresh endpoint."""

    def test_admin_refresh_jwks(self, client):
        """Test /admin/refresh-jwks endpoint."""
        import dependency_track_mcp.main

        dependency_track_mcp.main._jwks_cache = {"keys": []}

        response = client.post("/admin/refresh-jwks")

        assert response.status_code == 200
        data = response.json()
        assert "JWKS cache cleared" in data["message"]
        assert dependency_track_mcp.main._jwks_cache is None


class TestMainFunction:
    """Tests for main() server startup function."""

    def test_main_with_https_valid_config(self):
        """Test main() starts server with HTTPS."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_settings = MagicMock(spec=Settings)
            mock_settings.dev_allow_http = False
            mock_settings.server_tls_cert = (
                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
            )
            mock_settings.server_tls_key = (
                "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
            )
            mock_settings.server_host = "0.0.0.0"
            mock_settings.server_port = 8000
            mock_settings.oauth_jwks_url = "https://auth.example.com/.well-known/jwks.json"
            mock_settings.oauth_audience = None
            mock_settings.server_tls_keyfile_password = None
            mock_get_settings.return_value = mock_settings

            with patch.object(mock_settings, "validate_configuration_for_web_deployment"):
                with patch("dependency_track_mcp.main.materialize_tls_files") as mock_materialize:
                    mock_materialize.return_value = ("cert.pem", "key.pem", None)

                    with patch("uvicorn.run") as mock_uvicorn:
                        with patch("dependency_track_mcp.main.cleanup_tls_temp_files"):
                            main()

                            # Verify uvicorn was called with HTTPS settings
                            assert mock_uvicorn.called
                            call_kwargs = mock_uvicorn.call_args[1]
                            assert call_kwargs["ssl_certfile"] == "cert.pem"
                            assert call_kwargs["ssl_keyfile"] == "key.pem"

    def test_main_with_http_dev_mode(self):
        """Test main() in development HTTP mode."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_settings = MagicMock(spec=Settings)
            mock_settings.dev_allow_http = True
            mock_settings.server_tls_cert = None
            mock_settings.server_tls_key = None
            mock_settings.server_host = "localhost"
            mock_settings.server_port = 8000
            mock_settings.oauth_jwks_url = "https://auth.example.com/.well-known/jwks.json"
            mock_settings.oauth_audience = None
            mock_get_settings.return_value = mock_settings

            with patch.object(mock_settings, "validate_oauth_enabled"):
                with patch("uvicorn.run") as mock_uvicorn:
                    main()

                    # Verify uvicorn was called without HTTPS
                    assert mock_uvicorn.called
                    call_kwargs = mock_uvicorn.call_args[1]
                    assert "ssl_certfile" not in call_kwargs

    def test_main_web_deployment_validation_fails(self):
        """Test main() exits when web deployment validation fails."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_settings = MagicMock(spec=Settings)
            mock_settings.dev_allow_http = False
            mock_settings.server_tls_cert = None
            mock_settings.server_tls_key = None
            mock_settings.server_host = "0.0.0.0"
            mock_settings.server_port = 8000
            mock_settings.oauth_jwks_url = "https://auth.example.com/.well-known/jwks.json"
            mock_settings.oauth_audience = None
            mock_get_settings.return_value = mock_settings

            with patch.object(
                mock_settings,
                "validate_configuration_for_web_deployment",
                side_effect=ConfigurationError("TLS required"),
            ):
                with patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:
                    with pytest.raises(SystemExit):
                        main()
                    mock_exit.assert_called_with(1)

    def test_main_oauth_validation_fails(self):
        """Test main() exits when OAuth validation fails."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_settings = MagicMock(spec=Settings)
            mock_settings.dev_allow_http = True
            mock_settings.server_tls_cert = None
            mock_settings.server_tls_key = None
            mock_settings.server_host = "0.0.0.0"
            mock_settings.server_port = 8000
            mock_settings.oauth_jwks_url = "https://auth.example.com/.well-known/jwks.json"
            mock_settings.oauth_audience = None
            mock_get_settings.return_value = mock_settings

            with patch.object(
                mock_settings,
                "validate_oauth_enabled",
                side_effect=ConfigurationError("OAuth not configured"),
            ):
                with patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:
                    with pytest.raises(SystemExit):
                        main()
                    mock_exit.assert_called_with(1)

    def test_main_without_tls_non_dev_mode_exits(self):
        """Test main() exits when TLS missing in non-dev mode."""
        with patch("dependency_track_mcp.main.get_settings") as mock_get_settings:
            mock_settings = MagicMock(spec=Settings)
            mock_settings.dev_allow_http = False
            mock_settings.server_tls_cert = None
            mock_settings.server_tls_key = None
            mock_settings.server_host = "0.0.0.0"
            mock_settings.server_port = 8000
            mock_settings.oauth_jwks_url = "https://auth.example.com/.well-known/jwks.json"
            mock_settings.oauth_audience = None
            mock_get_settings.return_value = mock_settings

            with patch.object(mock_settings, "validate_configuration_for_web_deployment"):
                with patch("sys.exit", side_effect=SystemExit(1)) as mock_exit:
                    with pytest.raises(SystemExit):
                        main()
                    mock_exit.assert_called_with(1)
