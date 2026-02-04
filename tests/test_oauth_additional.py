"""Additional tests for oauth.py - missing coverage."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
import json
import base64
from datetime import datetime, UTC

from dependency_track_mcp.oauth import (
    JWTValidator,
    InvalidTokenError,
    InsufficientScopesError,
    JWTPayload,
    AuthorizationContext,
)


def create_valid_jwt_token(
    sub: str = "user123",
    iss: str = "https://auth.example.com",
    aud: str | list[str] | None = None,
    scope: str = "read:projects",
    exp_offset: int = 3600,
) -> str:
    """Create a valid-looking JWT token for testing.
    
    Note: This is NOT cryptographically signed, only for structure testing.
    """
    from datetime import datetime, timezone, timedelta
    
    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    exp = int((now + timedelta(seconds=exp_offset)).timestamp())
    
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "sub": sub,
        "iss": iss,
        "iat": iat,
        "exp": exp,
        "scope": scope,
    }
    if aud:
        payload["aud"] = aud
    
    # Encode (not signed, just base64)
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signature_b64 = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=").decode()
    
    return f"{header_b64}.{payload_b64}.{signature_b64}"


class TestJWTValidatorInit:
    """Test JWTValidator initialization edge cases."""

    def test_jwks_url_not_provided_no_issuer(self):
        """Test initialization without JWKS URL and without issuer."""
        validator = JWTValidator(
            expected_issuer=None,
            expected_audience=None,
            jwks_url=None,
        )
        assert validator.jwks_url is None

    def test_jwks_url_explicit_provided(self):
        """Test initialization with explicit JWKS URL."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
            jwks_url="https://custom.example.com/jwks",
        )
        assert validator.jwks_url == "https://custom.example.com/jwks"

    def test_jwks_url_auto_derived_keycloak(self):
        """Test JWKS URL auto-derivation for Keycloak."""
        validator = JWTValidator(
            expected_issuer="https://keycloak.example.com/realms/myrealm",
            expected_audience=None,
        )
        assert validator.jwks_url == "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"

    def test_jwks_url_auto_derived_generic_oidc(self):
        """Test JWKS URL auto-derivation for generic OIDC."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        assert validator.jwks_url == "https://auth.example.com/.well-known/jwks.json"


class TestJWTValidatorFetchJWKS:
    """Test JWKS fetching functionality."""

    @pytest.mark.asyncio
    async def test_fetch_jwks_cached(self):
        """Test that cached JWKS is returned without fetching."""
        jwks_data = {"keys": []}
        
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        # Manually set cache
        validator._jwks_cache = jwks_data
        
        # Should return cached value without making request
        result = await validator.fetch_jwks()
        assert result == jwks_data

    @pytest.mark.asyncio
    async def test_fetch_jwks_no_url_configured(self):
        """Test fetch JWKS when no URL is configured."""
        validator = JWTValidator(
            expected_issuer=None,
            expected_audience=None,
            jwks_url=None,
        )
        
        with pytest.raises(InvalidTokenError, match="JWKS URL not configured"):
            await validator.fetch_jwks()


class TestJWTValidatorClearCache:
    """Test JWKS cache clearing."""

    def test_clear_jwks_cache(self):
        """Test clearing JWKS cache."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        # Set cache
        validator._jwks_cache = {"keys": []}
        assert validator._jwks_cache is not None
        
        # Clear cache
        validator.clear_jwks_cache()
        assert validator._jwks_cache is None


class TestJWTValidatorDecodedPayload:
    """Test JWT payload decoding."""

    def test_decode_jwt_payload_invalid_format(self):
        """Test decoding with invalid JWT format."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        with pytest.raises(InvalidTokenError, match="Token must have 3 parts"):
            validator._decode_jwt_payload("invalid")

    def test_decode_jwt_payload_invalid_base64(self):
        """Test decoding with invalid base64."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        # Valid JWT format but invalid base64 in payload
        token = "header.!!!invalid!!!.signature"
        with pytest.raises(InvalidTokenError, match="Failed to decode JWT payload"):
            validator._decode_jwt_payload(token)

    def test_decode_jwt_payload_success(self):
        """Test successful JWT payload decoding."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        token = create_valid_jwt_token()
        payload = validator._decode_jwt_payload(token)
        
        assert payload["sub"] == "user123"
        assert payload["iss"] == "https://auth.example.com"
        assert payload["scope"] == "read:projects"


class TestValidateIssuer:
    """Test issuer validation."""

    def test_validate_issuer_mismatch(self):
        """Test issuer validation with mismatched issuer."""
        validator = JWTValidator(
            expected_issuer="https://expected.example.com",
            expected_audience=None,
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
            iss="https://different.example.com",
        )
        
        with pytest.raises(InvalidTokenError, match="does not match"):
            validator.validate_issuer(payload)

    def test_validate_issuer_missing(self):
        """Test issuer validation when iss claim is missing."""
        validator = JWTValidator(
            expected_issuer="https://expected.example.com",
            expected_audience=None,
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
        )
        
        with pytest.raises(InvalidTokenError, match="missing 'iss' claim"):
            validator.validate_issuer(payload)

    def test_validate_issuer_no_validation(self):
        """Test when no issuer validation is configured."""
        validator = JWTValidator(
            expected_issuer=None,
            expected_audience=None,
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
            iss="https://any.example.com",
        )
        
        # Should not raise
        validator.validate_issuer(payload)


class TestValidateAudience:
    """Test audience validation."""

    def test_validate_audience_no_validation(self):
        """Test when no audience validation is configured."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
            aud="any-client",
        )
        
        # Should not raise
        validator.validate_audience(payload)

    def test_validate_audience_single_match(self):
        """Test audience validation with matching single audience."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience="my-client",
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
            aud="my-client",
        )
        
        # Should not raise
        validator.validate_audience(payload)

    def test_validate_audience_list_match(self):
        """Test audience validation with matching audience in list."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience="my-client",
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
            aud=["other-client", "my-client"],
        )
        
        # Should not raise
        validator.validate_audience(payload)

    def test_validate_audience_missing(self):
        """Test audience validation when aud claim is missing."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
        )
        
        # Should not raise since no expected_audience is configured
        validator.validate_audience(payload)

    def test_validate_audience_missing_with_expected(self):
        """Test audience validation when aud claim is missing but expected."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience="my-client",
        )
        
        payload = JWTPayload(
            sub="user123",
            iat=1000000000,
            exp=2000000000,
        )
        
        with pytest.raises(InvalidTokenError, match="missing 'aud' claim"):
            validator.validate_audience(payload, expected_audience="my-client")


class TestValidateTokenStructure:
    """Test token structure validation."""

    def test_validate_token_structure_success(self):
        """Test successful token structure validation."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        token = create_valid_jwt_token()
        payload = validator.validate_token_structure(token)
        
        assert payload.sub == "user123"
        assert payload.iss == "https://auth.example.com"

    def test_validate_token_structure_missing_required_claim(self):
        """Test token structure validation with missing required claim."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )
        
        # Create a token with missing required claims
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"iss": "https://auth.example.com"}  # Missing sub, iat, exp
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signature_b64 = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=").decode()
        
        token = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        with pytest.raises(InvalidTokenError, match="Missing required JWT claims"):
            validator.validate_token_structure(token)
