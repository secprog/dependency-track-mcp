"""Tests for OAuth 2.1 authorization implementation."""

import base64
import json
from datetime import datetime, timedelta

import pytest

from dependency_track_mcp.oauth import (
    AuthorizationContext,
    InvalidTokenError,
    InsufficientScopesError,
    JWTPayload,
    JWTValidator,
    OAuth2AuthorizationMiddleware,
)


class TestJWTPayload:
    """Test JWT payload parsing and scope extraction."""

    def test_jwt_payload_with_scope_field(self):
        """Test JWT payload with 'scope' field."""
        payload = JWTPayload(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            scope="read:projects read:vulnerabilities",
        )
        scopes = payload.get_scopes()
        assert scopes == {"read:projects", "read:vulnerabilities"}

    def test_jwt_payload_with_scopes_field(self):
        """Test JWT payload with 'scopes' field (alternative)."""
        payload = JWTPayload(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            scopes="write:analysis upload:bom",
        )
        scopes = payload.get_scopes()
        assert scopes == {"write:analysis", "upload:bom"}

    def test_jwt_payload_with_no_scopes(self):
        """Test JWT payload with no scope claims."""
        payload = JWTPayload(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        )
        scopes = payload.get_scopes()
        assert scopes == set()

    def test_jwt_payload_with_empty_scopes(self):
        """Test JWT payload with empty scope string."""
        payload = JWTPayload(
            sub="user123",
            iat=int(datetime.utcnow().timestamp()),
            exp=int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
            scope="",
        )
        scopes = payload.get_scopes()
        assert scopes == set()


class TestJWTValidator:
    """Test JWT token validation."""

    @pytest.fixture
    def validator(self):
        """Create a JWT validator instance."""
        return JWTValidator(expected_issuer="https://auth.example.com")

    def _create_jwt(
        self,
        subject: str = "user123",
        scope: str = "read:projects",
        issuer: str = "https://auth.example.com",
        audience: str | None = None,
        expired: bool = False,
    ) -> str:
        """Create a test JWT token."""
        now = datetime.utcnow()
        exp_time = now - timedelta(minutes=1) if expired else now + timedelta(hours=1)

        payload = {
            "sub": subject,
            "iat": int(now.timestamp()),
            "exp": int(exp_time.timestamp()),
            "scope": scope,
            "iss": issuer,
        }
        if audience:
            payload["aud"] = audience

        # Encode payload (JWT format without actual signature)
        header = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip(
            "="
        )
        signature = base64.urlsafe_b64encode(b"signature").decode().rstrip("=")

        return f"{header}.{body}.{signature}"

    def test_jwt_structure_validation_valid_token(self, validator):
        """Test validation of valid JWT structure."""
        token = self._create_jwt()
        payload = validator.validate_token_structure(token)
        assert payload.sub == "user123"
        assert payload.scope == "read:projects"

    def test_jwt_structure_validation_malformed_token(self, validator):
        """Test validation fails for malformed JWT."""
        with pytest.raises(InvalidTokenError):
            validator.validate_token_structure("not.a.valid.token.format")

    def test_jwt_structure_validation_missing_parts(self, validator):
        """Test validation fails when token has incorrect number of parts."""
        with pytest.raises(InvalidTokenError):
            validator.validate_token_structure("two.parts")

    def test_jwt_expiration_validation_valid(self, validator):
        """Test expiration validation for valid token."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now + timedelta(hours=1)).timestamp()),
        )
        # Should not raise
        validator.validate_token_expiration(payload)

    def test_jwt_expiration_validation_expired(self, validator):
        """Test expiration validation for expired token."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now - timedelta(minutes=1)).timestamp()),
        )
        with pytest.raises(InvalidTokenError):
            validator.validate_token_expiration(payload)

    def test_jwt_issuer_validation_matches(self, validator):
        """Test issuer validation when issuer matches."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now + timedelta(hours=1)).timestamp()),
            iss="https://auth.example.com",
        )
        # Should not raise
        validator.validate_issuer(payload)

    def test_jwt_issuer_validation_mismatch(self, validator):
        """Test issuer validation fails for mismatched issuer."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now + timedelta(hours=1)).timestamp()),
            iss="https://different-issuer.com",
        )
        with pytest.raises(InvalidTokenError):
            validator.validate_issuer(payload)

    def test_jwt_issuer_validation_missing(self, validator):
        """Test issuer validation fails when issuer is missing."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now + timedelta(hours=1)).timestamp()),
        )
        with pytest.raises(InvalidTokenError):
            validator.validate_issuer(payload)

    def test_jwt_audience_validation_matches(self, validator):
        """Test audience validation when audience matches."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now + timedelta(hours=1)).timestamp()),
            aud="my-app",
        )
        # Should not raise
        validator.validate_audience(payload, expected_audience="my-app")

    def test_jwt_audience_validation_list_matches(self, validator):
        """Test audience validation when audience is in list."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now + timedelta(hours=1)).timestamp()),
            aud=["app1", "app2", "my-app"],
        )
        # Should not raise
        validator.validate_audience(payload, expected_audience="my-app")

    def test_jwt_audience_validation_mismatch(self, validator):
        """Test audience validation fails for mismatched audience."""
        now = datetime.utcnow()
        payload = JWTPayload(
            sub="user123",
            iat=int(now.timestamp()),
            exp=int((now + timedelta(hours=1)).timestamp()),
            aud="different-app",
        )
        with pytest.raises(InvalidTokenError):
            validator.validate_audience(payload, expected_audience="my-app")


@pytest.mark.asyncio
class TestAuthorizationContext:
    """Test authorization context."""

    def test_authorization_context_not_expired(self):
        """Test expired check for valid token."""
        now = datetime.utcnow()
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects"},
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        assert not context.is_expired()

    def test_authorization_context_expired(self):
        """Test expired check for expired token."""
        now = datetime.utcnow()
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects"},
            issued_at=now,
            expires_at=now - timedelta(minutes=1),
        )
        assert context.is_expired()

    def test_has_scope_true(self):
        """Test scope check when scope is present."""
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects", "read:vulnerabilities"},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        assert context.has_scope("read:projects")

    def test_has_scope_false(self):
        """Test scope check when scope is not present."""
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects"},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        assert not context.has_scope("write:projects")

    def test_has_any_scope_true(self):
        """Test any scope check when at least one scope is present."""
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects", "read:vulnerabilities"},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        required = {"write:projects", "read:projects"}
        assert context.has_any_scope(required)

    def test_has_any_scope_false(self):
        """Test any scope check when no scopes match."""
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects"},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        required = {"write:projects", "write:vulnerabilities"}
        assert not context.has_any_scope(required)

    def test_has_all_scopes_true(self):
        """Test all scopes check when all scopes are present."""
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects", "read:vulnerabilities", "write:analysis"},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        required = {"read:projects", "read:vulnerabilities"}
        assert context.has_all_scopes(required)

    def test_has_all_scopes_false(self):
        """Test all scopes check when not all scopes are present."""
        context = AuthorizationContext(
            token="test-token",
            subject="user123",
            scopes={"read:projects"},
            issued_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        required = {"read:projects", "read:vulnerabilities"}
        assert not context.has_all_scopes(required)


@pytest.mark.asyncio
class TestOAuth2AuthorizationMiddleware:
    """Test OAuth 2.1 authorization middleware."""

    @pytest.fixture
    def validator(self):
        """Create a JWT validator instance."""
        return JWTValidator(expected_issuer="https://auth.example.com")

    @pytest.fixture
    def middleware(self, validator):
        """Create middleware instance."""
        return OAuth2AuthorizationMiddleware(
            validator=validator,
            required_scopes={"read:projects", "read:vulnerabilities"},
        )

    @pytest.mark.asyncio
    async def test_validate_authorization_header_valid_bearer_token(self, middleware):
        """Test validation of valid Bearer token header."""
        now = datetime.utcnow()
        payload = {
            "sub": "user123",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "scope": "read:projects read:vulnerabilities",
            "iss": "https://auth.example.com",
        }

        header = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip(
            "="
        )
        signature = (
            base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
        )

        token = f"{header}.{body}.{signature}"
        auth_header = f"Bearer {token}"

        context = await middleware.validate_authorization_header(auth_header)
        assert context.subject == "user123"
        assert context.has_scope("read:projects")
        assert context.has_scope("read:vulnerabilities")

    async def test_validate_authorization_header_missing(self, middleware):
        """Test validation fails when Authorization header is missing."""
        with pytest.raises(InvalidTokenError):
            await middleware.validate_authorization_header(None)

    async def test_validate_authorization_header_invalid_format(self, middleware):
        """Test validation fails with invalid header format."""
        with pytest.raises(InvalidTokenError):
            await middleware.validate_authorization_header("InvalidHeader")

    async def test_validate_authorization_header_missing_bearer_prefix(
        self, middleware
    ):
        """Test validation fails when Bearer prefix is missing."""
        with pytest.raises(InvalidTokenError):
            await middleware.validate_authorization_header("token12345")

    async def test_validate_authorization_header_insufficient_scopes(
        self, middleware
    ):
        """Test validation fails when token has insufficient scopes."""
        now = datetime.utcnow()
        payload = {
            "sub": "user123",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "scope": "read:projects",  # Missing read:vulnerabilities
            "iss": "https://auth.example.com",
        }

        header = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip(
            "="
        )
        signature = (
            base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
        )

        token = f"{header}.{body}.{signature}"
        auth_header = f"Bearer {token}"

        with pytest.raises(InsufficientScopesError):
            await middleware.validate_authorization_header(auth_header)

    async def test_validate_authorization_header_custom_scopes(self, middleware):
        """Test validation with custom required scopes."""
        now = datetime.utcnow()
        payload = {
            "sub": "user123",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=1)).timestamp()),
            "scope": "write:analysis upload:bom",
            "iss": "https://auth.example.com",
        }

        header = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip(
            "="
        )
        signature = (
            base64.urlsafe_b64encode(b"signature").decode().rstrip("=")
        )

        token = f"{header}.{body}.{signature}"
        auth_header = f"Bearer {token}"

        # Should succeed with custom scopes
        context = await middleware.validate_authorization_header(
            auth_header,
            required_scopes={"write:analysis"},
        )
        assert context.has_scope("write:analysis")
