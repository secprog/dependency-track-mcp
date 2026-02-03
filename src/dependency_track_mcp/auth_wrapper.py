"""OAuth 2.1 Auth Wrapper for FastMCP with Keycloak Integration.

This module provides a FastAPI-based authentication wrapper that sits in front of
FastMCP and validates JWT tokens from Keycloak before proxying requests.

Architecture:
    Internet → Auth Wrapper (validates JWT) → FastMCP (localhost)

This follows the MCP OAuth 2.1 specification pattern where authentication is
handled at the transport layer, not inside the MCP server itself.

Key Features:
- JWT signature verification using Keycloak's JWKS endpoint
- Audience (aud) and issuer (iss) validation
- Serves /.well-known/oauth-protected-resource metadata
- Returns proper WWW-Authenticate challenges with resource metadata
- Proxies validated requests to FastMCP backend
"""

import logging
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from jose import jwt
from jose.exceptions import JWTError

from dependency_track_mcp.config import get_settings

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Dependency Track MCP Auth Wrapper",
    description="OAuth 2.1 authentication wrapper for FastMCP with Keycloak",
    version="0.1.0",
)

# Global JWKS cache (refreshed on demand)
_jwks_cache: Optional[dict] = None


async def get_jwks() -> dict:
    """Fetch JWKS (JSON Web Key Set) from Keycloak.
    
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
    
    return _jwks_cache


def refresh_jwks_cache():
    """Clear JWKS cache to force refresh on next request."""
    global _jwks_cache
    _jwks_cache = None
    logger.info("JWKS cache cleared")


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource_metadata():
    """Serve OAuth Protected Resource Metadata.
    
    This endpoint advertises the OAuth configuration for this MCP server.
    Clients use this to discover the authorization server.
    
    See: https://datatracker.ietf.org/doc/html/rfc8707
    """
    settings = get_settings()
    
    return JSONResponse({
        "resource": settings.oauth_resource_uri,
        "authorization_servers": [settings.oauth_issuer],
    })


def unauthorized_response() -> Response:
    """Return 401 Unauthorized with proper WWW-Authenticate header.
    
    The WWW-Authenticate header includes a link to the resource metadata,
    allowing clients to discover the authorization server.
    """
    settings = get_settings()
    
    return Response(
        status_code=401,
        headers={
            "WWW-Authenticate": (
                f'Bearer realm="mcp", '
                f'resource_metadata="{settings.oauth_resource_metadata_url}"'
            )
        },
        content="Unauthorized: Valid Bearer token required",
    )


async def verify_bearer_token(request: Request) -> Optional[dict]:
    """Verify Bearer token from Authorization header.
    
    Validates:
    1. Authorization header format (Bearer <token>)
    2. JWT signature using Keycloak JWKS
    3. Token expiration
    4. Issuer (iss claim)
    5. Audience (aud claim)
    
    Args:
        request: FastAPI request object
        
    Returns:
        JWT claims dictionary if valid, None otherwise
    """
    settings = get_settings()
    
    # Extract Authorization header
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        logger.warning("Missing or invalid Authorization header")
        return None
    
    token = auth_header.split(" ", 1)[1].strip()
    
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
            algorithms=["RS256"],  # Adjust if Keycloak uses other algorithms
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


@app.api_route("/mcp", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def mcp_proxy(request: Request):
    """Proxy MCP requests to FastMCP backend after JWT validation.
    
    Flow:
    1. Validate Bearer token from Authorization header
    2. If valid, forward request to FastMCP on localhost
    3. If invalid, return 401 with WWW-Authenticate challenge
    
    Args:
        request: FastAPI request object
        
    Returns:
        Proxied response from FastMCP or 401 Unauthorized
    """
    # Verify Bearer token
    claims = await verify_bearer_token(request)
    if claims is None:
        return unauthorized_response()
    
    # Token is valid - proxy to FastMCP backend
    settings = get_settings()
    fastmcp_url = f"http://{settings.fastmcp_host}:{settings.fastmcp_port}/mcp"
    
    logger.debug(f"Proxying {request.method} request to {fastmcp_url}")
    
    try:
        async with httpx.AsyncClient(timeout=None) as client:
            # Forward request to FastMCP
            upstream_response = await client.request(
                method=request.method,
                url=fastmcp_url,
                headers={
                    k: v for k, v in request.headers.items()
                    if k.lower() not in ["host", "authorization"]  # Strip auth header
                },
                content=await request.body(),
            )
            
            # Return FastMCP response
            return Response(
                content=upstream_response.content,
                status_code=upstream_response.status_code,
                headers=dict(upstream_response.headers),
                media_type=upstream_response.headers.get("content-type"),
            )
            
    except Exception as e:
        logger.error(f"Failed to proxy request to FastMCP: {e}")
        return Response(
            status_code=502,
            content=f"Bad Gateway: FastMCP backend unreachable: {e}",
        )


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring.
    
    Returns:
        Health status and JWKS cache state
    """
    settings = get_settings()
    
    return JSONResponse({
        "status": "healthy",
        "jwks_cached": _jwks_cache is not None,
        "oauth_issuer": settings.oauth_issuer,
        "fastmcp_backend": f"http://{settings.fastmcp_host}:{settings.fastmcp_port}",
    })


@app.post("/admin/refresh-jwks")
async def admin_refresh_jwks():
    """Admin endpoint to force JWKS cache refresh.
    
    Use this after Keycloak key rotation.
    
    In production, protect this endpoint with authentication.
    """
    refresh_jwks_cache()
    return JSONResponse({"message": "JWKS cache cleared, will refresh on next request"})


def main():
    """Run the auth wrapper server."""
    import uvicorn
    
    settings = get_settings()
    
    logger.info("=" * 80)
    logger.info("Starting Dependency Track MCP Auth Wrapper")
    logger.info("=" * 80)
    logger.info(f"Auth Wrapper: http://{settings.server_host}:{settings.server_port}")
    logger.info(f"FastMCP Backend: http://{settings.fastmcp_host}:{settings.fastmcp_port}")
    logger.info(f"OAuth Issuer: {settings.oauth_issuer}")
    logger.info(f"JWKS URL: {settings.oauth_jwks_url}")
    logger.info(f"Required Audience: {settings.oauth_audience or '(not enforced)'}")
    logger.info("=" * 80)
    
    uvicorn.run(
        app,
        host=settings.server_host,
        port=settings.server_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
