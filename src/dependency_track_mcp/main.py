"""Dependency Track MCP Server - Main Entry Point.

This module provides a FastAPI-based server with OAuth 2.1 authentication that integrates
FastMCP directly and validates JWT tokens from Keycloak/OIDC before handling MCP requests.

Architecture:
    Internet → Main Server (validates JWT + handles MCP via FastMCP)

This follows the MCP OAuth 2.1 specification pattern where authentication is
handled at the transport layer.

Key Features:
- JWT signature verification using JWKS endpoint
- Audience (aud) and issuer (iss) validation
- Serves /.well-known/oauth-protected-resource metadata
- Returns proper WWW-Authenticate challenges with resource metadata
- Direct integration with FastMCP (no separate HTTP server needed)
"""

import logging
import sys
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import jwt
from jose.exceptions import JWTError

from dependency_track_mcp.config import (
    ConfigurationError,
    cleanup_tls_temp_files,
    get_settings,
    materialize_tls_files,
)
from dependency_track_mcp.server import mcp as fastmcp_server

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Dependency Track MCP Server",
    description="MCP server with OAuth 2.1 authentication for OWASP Dependency Track",
    version="0.1.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global JWKS cache (refreshed on demand)
_jwks_cache: Optional[dict] = None


# Custom middleware to validate JWT tokens
class JWTAuthMiddleware:
    """Middleware to validate JWT tokens for /mcp endpoint."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # Only apply auth to /mcp path
        if scope["type"] == "http" and scope["path"].startswith("/mcp"):
            # Get authorization header
            headers = dict(scope.get("headers", []))
            auth_header = headers.get(b"authorization", b"").decode("utf-8")

            # Verify token
            if not auth_header.lower().startswith("bearer "):
                # No valid Bearer token - return 401
                settings = get_settings()
                response = Response(
                    status_code=401,
                    content="Unauthorized: Valid Bearer token required",
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer realm="mcp", '
                            f'resource_metadata="{settings.oauth_resource_metadata_url}"'
                        )
                    },
                )
                await response(scope, receive, send)
                return

            # Extract and verify token
            token = auth_header.split(" ", 1)[1].strip()

            try:
                claims = await verify_jwt_token(token)
                if claims is None:
                    # Invalid token - return 401
                    settings = get_settings()
                    response = Response(
                        status_code=401,
                        content="Unauthorized: Invalid or expired token",
                        headers={
                            "WWW-Authenticate": (
                                f'Bearer realm="mcp", '
                                f'resource_metadata="{settings.oauth_resource_metadata_url}"'
                            )
                        },
                    )
                    await response(scope, receive, send)
                    return

                # Token valid - store claims in scope for downstream use
                scope["jwt_claims"] = claims
                logger.debug(f"Authenticated request for subject: {claims.get('sub')}")

            except Exception as e:
                logger.error(f"JWT validation error: {e}")
                settings = get_settings()
                response = Response(
                    status_code=401,
                    content="Unauthorized: JWT validation failed",
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer realm="mcp", '
                            f'resource_metadata="{settings.oauth_resource_metadata_url}"'
                        )
                    },
                )
                await response(scope, receive, send)
                return

        # Continue to next middleware/app
        await self.app(scope, receive, send)


async def get_jwks() -> dict:
    """Fetch JWKS (JSON Web Key Set) from the OAuth provider.

    In production, you should implement:
    - TTL-based caching (e.g., cache for 1 hour)
    - Automatic refresh on cache expiry
    - Error handling with fallback

    Returns:
        JWKS dictionary with public keys

    Raises:
        Exception: If JWKS endpoint is unreachable
    """
    global _jwks_cache

    if _jwks_cache is None:
        settings = get_settings()
        jwks_url = settings.oauth_jwks_url

        if not jwks_url:
            raise ValueError("JWKS URL not configured")

        logger.info(f"Fetching JWKS from {jwks_url}")

        async with httpx.AsyncClient(timeout=10.0, verify=settings.verify_ssl) as client:
            try:
                response = await client.get(jwks_url)
                response.raise_for_status()
                _jwks_cache = response.json()
                logger.info("JWKS fetched and cached successfully")
            except Exception as e:
                logger.error(f"Failed to fetch JWKS from {jwks_url}: {e}")
                raise

    # Type assertion: _jwks_cache is not None at this point
    return _jwks_cache  # type: ignore


def refresh_jwks_cache():
    """Clear JWKS cache to force refresh on next request."""
    global _jwks_cache
    _jwks_cache = None
    logger.info("JWKS cache cleared")


async def verify_jwt_token(token: str) -> Optional[dict]:
    """Verify JWT token using JWKS.

    Args:
        token: JWT token string

    Returns:
        Token claims dictionary if valid, None otherwise
    """
    settings = get_settings()

    # Fetch JWKS
    try:
        jwks = await get_jwks()
    except Exception as e:
        logger.error(f"Failed to fetch JWKS: {e}")
        return None

    # Verify JWT signature and claims
    try:
        # python-jose automatically selects the correct key from JWKS using 'kid'
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],  # Adjust if using other algorithms
            issuer=settings.oauth_issuer,
            audience=settings.oauth_audience,
            options={
                "verify_signature": True,
                "verify_aud": bool(settings.oauth_audience),  # Only verify if configured
                "verify_iat": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_sub": True,
                "verify_at_hash": False,  # Not used in access tokens
            },
        )

        logger.info(f"Token validated successfully for subject: {claims.get('sub')}")
        logger.debug(f"Token claims: {claims}")

        return claims

    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        # Try refreshing JWKS cache in case keys were rotated
        refresh_jwks_cache()
        return None
    except Exception as e:
        logger.error(f"Unexpected error during JWT validation: {e}")
        return None


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    """Serve OAuth Protected Resource Metadata.

    This endpoint advertises the OAuth configuration for this MCP server.
    Clients use this to discover the authorization server.

    See: https://datatracker.ietf.org/doc/html/rfc8707
    """
    settings = get_settings()

    return JSONResponse(
        {
            "resource": settings.oauth_resource_uri,
            "authorization_servers": [settings.oauth_issuer],
        }
    )


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring.

    Returns:
        Health status and JWKS cache state
    """
    settings = get_settings()

    return JSONResponse(
        {
            "status": "healthy",
            "jwks_cached": _jwks_cache is not None,
            "oauth_issuer": settings.oauth_issuer,
            "mcp_integrated": True,
        }
    )


@app.post("/admin/refresh-jwks")
async def admin_refresh_jwks():
    """Admin endpoint to force JWKS cache refresh.

    Use this after key rotation.

    In production, protect this endpoint with authentication.
    """
    refresh_jwks_cache()
    return JSONResponse({"message": "JWKS cache cleared, will refresh on next request"})


# Mount FastMCP's HTTP app at /mcp with JWT auth middleware
# This allows FastMCP to handle the MCP protocol while we handle authentication
mcp_http_app = fastmcp_server.http_app(path="/mcp")
app.add_middleware(JWTAuthMiddleware)
app.mount("/mcp", mcp_http_app)


def main():
    """Run the MCP server with OAuth authentication."""
    import uvicorn

    settings = get_settings()

    # In dev mode with HTTP allowed, skip strict web deployment validation
    if not settings.dev_allow_http:
        try:
            settings.validate_configuration_for_web_deployment()
        except ConfigurationError as e:
            logger.error("=" * 80)
            logger.error("SECURITY CONFIGURATION ERROR - SERVER CANNOT START")
            logger.error("=" * 80)
            logger.error(str(e))
            logger.error("=" * 80)
            sys.exit(1)
    else:
        # Dev mode - still validate OAuth is enabled
        try:
            settings.validate_oauth_enabled()
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            sys.exit(1)
        logger.warning("=" * 80)
        logger.warning("DEVELOPMENT MODE - HTTP ALLOWED (NOT FOR PRODUCTION)")
        logger.warning("=" * 80)

    # Determine if using HTTPS or HTTP
    use_https = settings.server_tls_cert and settings.server_tls_key
    protocol = "https" if use_https else "http"

    logger.info("=" * 80)
    logger.info("Starting Dependency Track MCP Server with OAuth")
    logger.info("=" * 80)
    logger.info(f"Server: {protocol}://{settings.server_host}:{settings.server_port}")
    logger.info("OAuth Issuer: configured (value not logged)")
    logger.info(f"JWKS URL: {settings.oauth_jwks_url}")
    if settings.oauth_audience:
        logger.info("Required Audience: configured (value not logged)")
    else:
        logger.info("Required Audience: (not enforced)")
    logger.info(f"MCP Integration: Direct (no separate FastMCP HTTP server)")
    logger.info("=" * 80)

    if use_https:
        certfile, keyfile, ca_certs = materialize_tls_files(settings)
        try:
            uvicorn.run(
                app,
                host=settings.server_host,
                port=settings.server_port,
                log_level="info",
                ssl_certfile=certfile,
                ssl_keyfile=keyfile,
                ssl_ca_certs=ca_certs,
                ssl_keyfile_password=settings.server_tls_keyfile_password,
            )
        finally:
            cleanup_tls_temp_files()
    else:
        # HTTP mode (dev only)
        if not settings.dev_allow_http:
            logger.error(
                "TLS certificates required for production. "
                "Set MCP_SERVER_TLS_CERT and MCP_SERVER_TLS_KEY."
            )
            sys.exit(1)
        uvicorn.run(
            app,
            host=settings.server_host,
            port=settings.server_port,
            log_level="info",
        )


if __name__ == "__main__":
    main()
