"""Tests for oauth.py token validation methods.

Covers lines 172-183, 335-336, 357-380, 385-386.
"""

import base64
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from dependency_track_mcp.oauth import (
    AuthorizationContext,
    InsufficientScopesError,
    InvalidTokenError,
    JWTPayload,
    JWTValidator,
)


def create_jwt_token(
    sub: str = "user123",
    iss: str = "https://auth.example.com",
    aud: str | list[str] | None = None,
    scope: str = "read:projects",
    exp_offset: int = 3600,
    **extra_claims,
) -> str:
    """Create a valid-looking JWT token for testing."""
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
    payload.update(extra_claims)

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signature_b64 = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=").decode()

    return f"{header_b64}.{payload_b64}.{signature_b64}"


class TestValidateTokenExpiration:
    """Test token expiration validation."""

    def test_validate_token_expiration_valid(self):
        """Test validation with non-expired token."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        payload = JWTPayload(
            sub="user123",
            iat=int(datetime.now(timezone.utc).timestamp()),
            exp=int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        )

        # Should not raise
        validator.validate_token_expiration(payload)

    def test_validate_token_expiration_expired(self):
        """Test validation with expired token."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        # Token expired 1 hour ago
        exp_time = datetime.now(timezone.utc) - timedelta(hours=1)
        payload = JWTPayload(
            sub="user123",
            iat=int((exp_time - timedelta(hours=2)).timestamp()),
            exp=int(exp_time.timestamp()),
        )

        with pytest.raises(InvalidTokenError, match="Token expired"):
            validator.validate_token_expiration(payload)

    def test_validate_token_expiration_boundary(self):
        """Test token at exact expiration time."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        # Token expiring right now
        now = datetime.now(timezone.utc).replace(microsecond=0)
        payload = JWTPayload(
            sub="user123",
            iat=int((now - timedelta(hours=1)).timestamp()),
            exp=int(now.timestamp()),
        )

        with pytest.raises(InvalidTokenError, match="Token expired"):
            validator.validate_token_expiration(payload)


class TestValidateTokenMethod:
    """Test the main validate_token async method."""

    @pytest.mark.asyncio
    async def test_validate_token_missing_jwks_url(self):
        """Test token validation when JWKS URL not configured."""
        validator = JWTValidator(
            expected_issuer=None,
            expected_audience=None,
            jwks_url=None,
        )

        token = create_jwt_token()

        with pytest.raises(InvalidTokenError, match="JWKS URL not configured"):
            await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_jwt_decode_error_with_retry(self):
        """Test token validation handles JWT decode errors and retries with refresh."""
        from jose.exceptions import JWTError

        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        # Mock JWKS fetching
        jwks_data = {"keys": []}

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            # First call returns old JWKS, second call (with refresh=True) returns new JWKS
            mock_fetch.side_effect = [jwks_data, jwks_data]

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                # First call fails, second call succeeds
                from datetime import datetime, timezone

                now = datetime.now(timezone.utc)

                successful_claims = {
                    "sub": "user123",
                    "iss": "https://auth.example.com",
                    "iat": int(now.timestamp()),
                    "exp": int((now + timedelta(hours=1)).timestamp()),
                    "scope": "read:projects",
                }

                mock_decode.side_effect = [
                    JWTError("Key not found"),
                    successful_claims,
                ]

                token = create_jwt_token()
                result = await validator.validate_token(token)

                assert result.subject == "user123"
                assert "read:projects" in result.scopes
                # Verify fetch_jwks was called twice (once normal, once with refresh)
                assert mock_fetch.call_count == 2
                mock_fetch.assert_called_with(refresh=True)

    @pytest.mark.asyncio
    async def test_validate_token_jwt_decode_error_both_fail(self):
        """Test token validation when both JWT decode attempts fail."""
        from jose.exceptions import JWTError

        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        jwks_data = {"keys": []}

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                mock_decode.side_effect = JWTError("Invalid signature")

                token = create_jwt_token()

                with pytest.raises(InvalidTokenError, match="JWT validation failed"):
                    await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_invalid_claims(self):
        """Test token validation with invalid claims after successful decode."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        jwks_data = {"keys": []}

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                # Return claims that can't be parsed into JWTPayload
                mock_decode.return_value = {"iss": "example.com"}  # Missing required sub, iat, exp

                token = create_jwt_token()

                with pytest.raises(InvalidTokenError, match="Invalid JWT claims"):
                    await validator.validate_token(token)

    @pytest.mark.asyncio
    async def test_validate_token_with_required_scopes_missing(self):
        """Test token validation fails when required scopes are missing."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        jwks_data = {"keys": []}
        now = datetime.now(timezone.utc)
        claims = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "scope": "read:projects",  # Only has read scope
        }

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                mock_decode.return_value = claims

                token = create_jwt_token()

                with pytest.raises(InsufficientScopesError, match="missing required scopes"):
                    await validator.validate_token(
                        token,
                        required_scopes={"read:projects", "write:projects"},
                    )

    @pytest.mark.asyncio
    async def test_validate_token_with_required_scopes_present(self):
        """Test token validation succeeds when all required scopes are present."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        jwks_data = {"keys": []}
        now = datetime.now(timezone.utc)
        claims = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "scope": "read:projects write:projects admin:config",
        }

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                mock_decode.return_value = claims

                token = create_jwt_token()
                result = await validator.validate_token(
                    token,
                    required_scopes={"read:projects", "write:projects"},
                )

                assert result.subject == "user123"
                assert "read:projects" in result.scopes
                assert "write:projects" in result.scopes

    @pytest.mark.asyncio
    async def test_validate_token_with_custom_audience(self):
        """Test token validation with custom expected audience."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience="default-client",
        )

        jwks_data = {"keys": []}
        now = datetime.now(timezone.utc)
        claims = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "aud": "custom-client",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "scope": "read:projects",
        }

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                mock_decode.return_value = claims

                token = create_jwt_token()
                result = await validator.validate_token(
                    token,
                    expected_audience="custom-client",
                )

                assert result.subject == "user123"
                assert result.audience == "custom-client"

    @pytest.mark.asyncio
    async def test_validate_token_creates_context(self):
        """Test that validate_token returns correct AuthorizationContext."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience="my-client",
        )

        jwks_data = {"keys": []}
        now = datetime.now(timezone.utc)
        iat_ts = int(now.timestamp())
        exp_ts = int((now + timedelta(hours=1)).timestamp())

        claims = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "aud": "my-client",
            "iat": iat_ts,
            "exp": exp_ts,
            "scope": "read:projects write:projects",
        }

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                mock_decode.return_value = claims

                token = "test.token.value"
                result = await validator.validate_token(token)

                assert isinstance(result, AuthorizationContext)
                assert result.token == token
                assert result.subject == "user123"
                assert result.issuer == "https://auth.example.com"
                assert result.audience == "my-client"
                assert result.scopes == {"read:projects", "write:projects"}
                assert not result.is_expired()
                assert result.has_scope("read:projects")
                assert result.has_scope("write:projects")

    @pytest.mark.asyncio
    async def test_validate_token_with_scopes_field_instead_of_scope(self):
        """Test token validation with 'scopes' field instead of 'scope'."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        jwks_data = {"keys": []}
        now = datetime.now(timezone.utc)
        claims = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "scopes": "read:projects write:projects",  # Using 'scopes' instead of 'scope'
        }

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                mock_decode.return_value = claims

                token = create_jwt_token()
                result = await validator.validate_token(token)

                assert result.scopes == {"read:projects", "write:projects"}

    @pytest.mark.asyncio
    async def test_validate_token_with_no_scopes(self):
        """Test token validation with no scopes in token."""
        validator = JWTValidator(
            expected_issuer="https://auth.example.com",
            expected_audience=None,
        )

        jwks_data = {"keys": []}
        now = datetime.now(timezone.utc)
        claims = {
            "sub": "user123",
            "iss": "https://auth.example.com",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            # No scope or scopes field
        }

        with patch.object(validator, "fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks_data

            with patch("dependency_track_mcp.oauth.jwt.decode") as mock_decode:
                mock_decode.return_value = claims

                token = create_jwt_token()
                result = await validator.validate_token(token)

                assert result.scopes == set()
