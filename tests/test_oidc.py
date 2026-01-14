"""Tests for oidc module."""

from unittest.mock import Mock, patch

import jwt
import pytest
import requests

from pia.oidc import TokenVerificationError, verify_token


class TestVerifyToken:
    @patch("pia.oidc.jwt.decode")
    @patch("pia.oidc.jwt.PyJWKClient")
    @patch("pia.oidc.requests.get")
    def test_verify_token_success(self, mock_get, mock_pyjwk, mock_decode):
        """Test token verification."""
        token = "test.jwt.token"
        issuer = "https://example.com"
        expected_audience = "test-audience"

        mock_signing_key = Mock()
        mock_signing_key.key = "mock-key"

        mock_jwks_client = Mock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        mock_issuer_response = Mock()
        mock_issuer_response.json.return_value = {
            "jwks_uri": "https://example.com/.well-known/jwks"
        }

        # Mock issuer config request json response
        mock_get.return_value = mock_issuer_response

        # Mock public keys request response
        mock_pyjwk.return_value = mock_jwks_client

        # Mock jwt.decode result
        mock_decode.return_value = "mock_claims"

        result = verify_token(token, issuer, expected_audience)

        # Assert result is return value of jwt.decode
        assert result == "mock_claims"

        # Assert issuer config request
        mock_get.assert_called_once_with(
            f"{issuer}/.well-known/openid-configuration", timeout=10
        )

        # Assert public keys request
        mock_pyjwk.assert_called_once_with("https://example.com/.well-known/jwks")

        # Assert jwt.decode call
        mock_decode.assert_called_once_with(
            token,
            "mock-key",
            algorithms=["RS256"],
            audience=expected_audience,
            options=dict(
                verify_signature=True,
                verify_exp=True,
                verify_aud=True,
                verify_iat=True,
                require={"aud", "exp", "iat"},
            ),
        )

    @patch("pia.oidc.requests.get")
    def test_verify_token_oidc_config_fetch_error(self, mock_get):
        """Test error when OIDC config fetch fails."""
        mock_get.side_effect = requests.RequestException()
        with pytest.raises(
            TokenVerificationError, match="Failed to fetch OIDC configuration"
        ):
            verify_token("token", "issuer", "audience")

    @patch("pia.oidc.requests.get")
    def test_verify_token_missing_jwks_uri(self, mock_get):
        """Test error when OIDC config missing jwks_uri."""
        mock_response = Mock()
        mock_response.json.return_value = {}  # missing 'jwks_uri'
        mock_get.return_value = mock_response

        with pytest.raises(TokenVerificationError, match="missing 'jwks_uri'"):
            verify_token("token", "issuer", "audience")

    @patch("pia.oidc.jwt.decode")
    @patch("pia.oidc.jwt.PyJWKClient")
    @patch("pia.oidc.requests.get")
    def test_verify_token_invalid_signature(self, mock_get, mock_pyjwk, mock_decode):
        """Test token decoding error."""
        mock_signing_key = Mock()
        mock_signing_key.key = "mock-key"

        mock_jwks_client = Mock()
        mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

        mock_response = Mock()
        mock_response.json.return_value = {"jwks_uri": "https://example.com/jwks"}

        mock_get.return_value = mock_response
        mock_pyjwk.return_value = mock_jwks_client
        mock_decode.side_effect = jwt.InvalidSignatureError("Invalid signature")

        with pytest.raises(TokenVerificationError):
            verify_token("token", "issuer", "audience")
