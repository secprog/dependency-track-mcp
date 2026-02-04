"""
Tests for oauth.py logging and logger coverage.
Targets logger.info statements in JWKS fetching.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dependency_track_mcp.oauth import JWTValidator


class TestJWTValidatorLogging:
    """Tests for JWT validator logging coverage."""

    @pytest.mark.asyncio
    async def test_fetch_jwks_with_logging(self):
        """Test fetch_jwks logs correctly during successful fetch."""
        validator = JWTValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            expected_issuer="https://auth.example.com",
            expected_audience="api",
        )

        # Mock the JWKS response
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.json = MagicMock(
            return_value={
                "keys": [
                    {
                        "kty": "RSA",
                        "n": "test_n",
                        "e": "AQAB",
                        "kid": "key-1",
                        "use": "sig",
                    }
                ]
            }
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock()

            with patch("dependency_track_mcp.oauth.logger") as mock_logger:
                # Fetch JWKS
                jwks = await validator.fetch_jwks()

                # Verify JWKS was fetched
                assert jwks is not None
                assert "keys" in jwks

                # Verify logging calls (these are the lines 178-180)
                assert mock_logger.info.call_count >= 1
                calls = [str(call) for call in mock_logger.info.call_args_list]
                # Check that at least one info log mentions "Fetching JWKS"
                info_logs = [
                    call for call in calls if "Fetching" in call or "fetched" in call.lower()
                ]
                assert len(info_logs) > 0, f"Expected info log about JWKS, got: {calls}"

    @pytest.mark.asyncio
    async def test_fetch_jwks_caches_successfully(self):
        """Test that JWKS is cached after successful fetch."""
        validator = JWTValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            expected_issuer="https://auth.example.com",
            expected_audience="api",
        )

        jwks_data = {
            "keys": [
                {
                    "kty": "RSA",
                    "n": "test_n",
                    "e": "AQAB",
                    "kid": "key-1",
                    "use": "sig",
                }
            ]
        }

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.json = MagicMock(return_value=jwks_data)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock()

            # First call - should fetch
            jwks1 = await validator.fetch_jwks()
            assert jwks1 == jwks_data

            # Second call - should return cached (no additional network call)
            jwks2 = await validator.fetch_jwks()
            assert jwks2 == jwks_data
            assert jwks2 is jwks1  # Same object (cached)

            # Verify only one network call was made (caching works)
            assert mock_client.get.call_count == 1
