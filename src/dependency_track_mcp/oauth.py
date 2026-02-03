"""OAuth 2.1 Authorization implementation for MCP Server.

This module implements OAuth 2.1 authorization as defined in:
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

Supports:
- Bearer token validation with JWKS-based signature verification
- JWT token parsing and verification using python-jose
- Scope-based access control
- Authorization context management
- Keycloak integration
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, UTC
from typing import Any, Optional, Set
from urllib.parse import urljoin

import httpx
from jose import jwt
from jose.exceptions import JWTError
from pydantic import BaseModel, Field, ValidationError as PydanticValidationError

logger = logging.getLogger(__name__)


class OAuth2Error(Exception):
    """Base exception for OAuth 2.1 errors."""

    pass


class InvalidTokenError(OAuth2Error):
    """Invalid or malformed token."""

    pass


class InsufficientScopesError(OAuth2Error):
    """Token does not have required scopes."""

    pass


class JWTPayload(BaseModel):
    """JWT token payload structure."""

    sub: str = Field(..., description="Subject (user/client identifier)")
    iat: int = Field(..., description="Issued at (Unix timestamp)")
    exp: int = Field(..., description="Expiration time (Unix timestamp)")
    scopes: Optional[str] = Field(
        default=None,
        description='Space-separated list of scopes, or "scope" field',
    )
    scope: Optional[str] = Field(
        default=None,
        description="Space-separated list of scopes (alternative field)",
    )
    aud: Optional[str | list[str]] = Field(
        default=None,
        description="Audience",
    )
    iss: Optional[str] = Field(
        default=None,
        description="Issuer",
    )

    def get_scopes(self) -> Set[str]:
        """Extract scopes from token payload."""
        scopes_str = self.scopes or self.scope or ""
        return set(scope.strip() for scope in scopes_str.split() if scope.strip())


@dataclass
class AuthorizationContext:
    """Context for OAuth 2.1 authorized requests."""

    token: str
    subject: str  # User/client identifier
    scopes: Set[str]  # Granted scopes
    issued_at: datetime
    expires_at: datetime
    issuer: Optional[str] = None
    audience: Optional[str | list[str]] = None

    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(UTC).replace(tzinfo=None) >= self.expires_at

    def has_scope(self, required_scope: str) -> bool:
        """Check if token has the required scope."""
        return required_scope in self.scopes

    def has_any_scope(self, required_scopes: Set[str]) -> bool:
        """Check if token has any of the required scopes."""
        return bool(required_scopes & self.scopes)

    def has_all_scopes(self, required_scopes: Set[str]) -> bool:
        """Check if token has all required scopes."""
        return required_scopes.issubset(self.scopes)


class JWTValidator:
    """Validates JWT tokens for OAuth 2.1 compliance with JWKS-based signature verification.

    This implementation:
    - Fetches JWKS (JSON Web Key Set) from the authorization server
    - Performs cryptographic signature verification using python-jose
    - Validates token claims (exp, iss, aud, etc.)
    - Caches JWKS for performance (with refresh capability)
    
    Supports Keycloak and other OIDC-compliant authorization servers.
    """

    def __init__(
        self,
        expected_issuer: Optional[str] = None,
        jwks_url: Optional[str] = None,
        expected_audience: Optional[str] = None,
    ):
        """Initialize JWT validator.

        Args:
            expected_issuer: Expected token issuer URL
            jwks_url: JWKS endpoint URL (auto-derived from issuer if not provided)
            expected_audience: Expected audience claim value
        """
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self._cache_lock = asyncio.Lock()
        self._jwks_cache: Optional[dict[str, Any]] = None
        
        # Derive JWKS URL if not provided
        if jwks_url:
            self.jwks_url = jwks_url
        elif expected_issuer:
            # Auto-derive JWKS URL from issuer
            if "/realms/" in expected_issuer:
                # Keycloak format: https://keycloak.example.com/realms/myrealm
                self.jwks_url = f"{expected_issuer}/protocol/openid-connect/certs"
            else:
                # Generic OIDC format
                self.jwks_url = f"{expected_issuer}/.well-known/jwks.json"
        else:
            self.jwks_url = None

    async def fetch_jwks(self, refresh: bool = False) -> dict[str, Any]:
        """Fetch JWKS from authorization server.
        
        Implements caching to avoid excessive network requests.
        In production, consider TTL-based refresh (e.g., cache for 1 hour).
        
        Args:
            refresh: Force refresh the cache
            
        Returns:
            JWKS dictionary
            
        Raises:
            InvalidTokenError: If JWKS cannot be fetched
        """
        async with self._cache_lock:
            if self._jwks_cache is not None and not refresh:
                return self._jwks_cache
            
            if not self.jwks_url:
                raise InvalidTokenError("JWKS URL not configured")
            
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    logger.info(f"Fetching JWKS from {self.jwks_url}")
                    response = await client.get(self.jwks_url)
                    response.raise_for_status()
                    self._jwks_cache = response.json()
                    logger.info("JWKS fetched and cached successfully")
                    # Type assertion: _jwks_cache is definitely not None after assignment
                    return self._jwks_cache  # type: ignore
            except Exception as e:
                logger.error(f"Failed to fetch JWKS from {self.jwks_url}: {e}")
                raise InvalidTokenError(f"Failed to fetch JWKS: {e}")

    def clear_jwks_cache(self):
        """Clear JWKS cache to force refresh on next validation.
        
        Call this after key rotation or if validation fails unexpectedly.
        """
        self._jwks_cache = None
        logger.info("JWKS cache cleared")

    def _decode_jwt_payload(self, token: str) -> dict[str, Any]:
        """Decode JWT payload without verification.

        Args:
            token: Bearer token (JWT format)

        Returns:
            Decoded JWT payload as dictionary

        Raises:
            InvalidTokenError: If token is malformed
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidTokenError("Token must have 3 parts (header.payload.signature)")

        try:
            # Add padding if needed
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding:
                payload += "=" * padding

            decoded = json.loads(__import__("base64").b64decode(payload))
            return decoded
        except Exception as e:
            raise InvalidTokenError(f"Failed to decode JWT payload: {e}")

    def validate_token_structure(self, token: str) -> JWTPayload:
        """Validate JWT token structure and required claims.

        Args:
            token: Bearer token (JWT format)

        Returns:
            Validated JWT payload

        Raises:
            InvalidTokenError: If token structure is invalid
        """
        try:
            payload_dict = self._decode_jwt_payload(token)
            return JWTPayload(**payload_dict)
        except PydanticValidationError as e:
            raise InvalidTokenError(f"Missing required JWT claims: {e}")
        except InvalidTokenError:
            raise

    def validate_token_expiration(self, payload: JWTPayload) -> None:
        """Validate token expiration.

        Args:
            payload: JWT payload

        Raises:
            InvalidTokenError: If token is expired
        """
        exp_timestamp = payload.exp
        exp_time = datetime.fromtimestamp(exp_timestamp, UTC).replace(tzinfo=None)

        if datetime.now(UTC).replace(tzinfo=None) >= exp_time:
            raise InvalidTokenError(
                f"Token expired at {exp_time.isoformat()}",
            )

    def validate_issuer(self, payload: JWTPayload) -> None:
        """Validate token issuer if expected issuer is configured.

        Args:
            payload: JWT payload

        Raises:
            InvalidTokenError: If issuer doesn't match
        """
        if not self.expected_issuer:
            return

        if not payload.iss:
            raise InvalidTokenError("Token missing 'iss' claim")

        if payload.iss != self.expected_issuer:
            raise InvalidTokenError(
                f"Token issuer {payload.iss} does not match expected issuer "
                f"{self.expected_issuer}",
            )

    def validate_audience(
        self,
        payload: JWTPayload,
        expected_audience: Optional[str] = None,
    ) -> None:
        """Validate token audience if specified.

        Args:
            payload: JWT payload
            expected_audience: Expected audience value

        Raises:
            InvalidTokenError: If audience doesn't match
        """
        if not expected_audience:
            return

        if not payload.aud:
            raise InvalidTokenError("Token missing 'aud' claim")

        audiences = (
            payload.aud if isinstance(payload.aud, list) else [payload.aud]
        )

        if expected_audience not in audiences:
            raise InvalidTokenError(
                f"Token audience {payload.aud} does not match expected audience "
                f"{expected_audience}",
            )

    async def validate_token(
        self,
        token: str,
        required_scopes: Optional[Set[str]] = None,
        expected_audience: Optional[str] = None,
    ) -> AuthorizationContext:
        """Validate OAuth 2.1 token with JWKS-based signature verification.

        Args:
            token: Bearer token
            required_scopes: Set of required scopes
            expected_audience: Expected audience claim (overrides instance default)

        Returns:
            AuthorizationContext with token claims and scopes

        Raises:
            InvalidTokenError: If token is invalid or signature verification fails
            InsufficientScopesError: If token lacks required scopes
        """
        # Use instance default audience if not provided
        aud_to_validate = expected_audience or self.expected_audience
        
        # Fetch JWKS for signature verification
        try:
            jwks = await self.fetch_jwks()
        except InvalidTokenError:
            raise
        
        # Verify JWT signature and claims using python-jose
        try:
            claims = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],  # Most common; add others if needed
                issuer=self.expected_issuer,
                audience=aud_to_validate,
                options={
                    "verify_signature": True,
                    "verify_aud": bool(aud_to_validate),
                    "verify_iat": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": bool(self.expected_issuer),
                    "verify_sub": True,
                    "verify_at_hash": False,  # Not used in access tokens
                },
            )
        except JWTError as e:
            logger.warning(f"JWT validation failed: {e}")
            # Try refreshing JWKS cache in case of key rotation
            try:
                jwks = await self.fetch_jwks(refresh=True)
                claims = jwt.decode(
                    token,
                    jwks,
                    algorithms=["RS256"],
                    issuer=self.expected_issuer,
                    audience=aud_to_validate,
                    options={
                        "verify_signature": True,
                        "verify_aud": bool(aud_to_validate),
                        "verify_iat": True,
                        "verify_exp": True,
                        "verify_nbf": True,
                        "verify_iss": bool(self.expected_issuer),
                        "verify_sub": True,
                        "verify_at_hash": False,
                    },
                )
            except JWTError as retry_error:
                raise InvalidTokenError(f"JWT validation failed: {retry_error}")
        
        # Parse claims into JWTPayload for scope extraction
        try:
            payload = JWTPayload(**claims)
        except PydanticValidationError as e:
            raise InvalidTokenError(f"Invalid JWT claims: {e}")
        
        # Extract scopes
        token_scopes = payload.get_scopes()

        # Check required scopes
        if required_scopes and not required_scopes.issubset(token_scopes):
            missing_scopes = required_scopes - token_scopes
            raise InsufficientScopesError(
                f"Token missing required scopes: {', '.join(sorted(missing_scopes))}",
            )

        # Create authorization context
        context = AuthorizationContext(
            token=token,
            subject=payload.sub,
            scopes=token_scopes,
            issued_at=datetime.fromtimestamp(payload.iat, UTC).replace(tzinfo=None),
            expires_at=datetime.fromtimestamp(payload.exp, UTC).replace(tzinfo=None),
            issuer=payload.iss,
            audience=payload.aud,
        )
        
        logger.info(f"Token validated successfully for subject: {context.subject}")

        return context


class OAuth2AuthorizationMiddleware:
    """Middleware for OAuth 2.1 authorization in MCP requests.

    This middleware enforces OAuth 2.1 bearer token validation for all
    protected resources.
    """

    def __init__(
        self,
        validator: JWTValidator,
        required_scopes: Optional[Set[str]] = None,
        exclude_paths: Optional[Set[str]] = None,
    ):
        """Initialize authorization middleware.

        Args:
            validator: JWT token validator
            required_scopes: Default required scopes for all paths
            exclude_paths: Paths that don't require authorization
        """
        self.validator = validator
        self.required_scopes = required_scopes or set()
        self.exclude_paths = exclude_paths or set()

    async def validate_authorization_header(
        self,
        authorization_header: Optional[str],
        required_scopes: Optional[Set[str]] = None,
    ) -> AuthorizationContext:
        """Validate Authorization header and extract context.

        Args:
            authorization_header: Authorization header value
            required_scopes: Required scopes for this request

        Returns:
            AuthorizationContext

        Raises:
            InvalidTokenError: If no valid Bearer token found
            InsufficientScopesError: If token lacks required scopes
        """
        if not authorization_header:
            raise InvalidTokenError("Missing Authorization header")

        parts = authorization_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise InvalidTokenError(
                "Authorization header must be 'Bearer <token>'",
            )

        token = parts[1]
        scopes = required_scopes or self.required_scopes

        return await self.validator.validate_token(
            token,
            required_scopes=scopes if scopes else None,
        )
