"""Tests for oidc module."""

import itertools
import json
import time
from unittest.mock import MagicMock, call, patch

import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

from pia.oidc import MAX_RESPONSE_SIZE, TokenVerificationError, verify_token

ISSUER = "https://example.com"
CONFIG_URL = f"{ISSUER}/.well-known/openid-configuration"
JWKS_URI = f"{ISSUER}/.well-known/jwks"
AUDIENCE = "test-audience"
KID = "test-kid"


@pytest.fixture(scope="module")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_jwk(private_key, kid=KID, use="sig"):
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk["kid"] = kid
    if use is not None:
        jwk["use"] = use
    return jwk


def make_token(private_key, kid=KID):
    now = int(time.time())
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 60},
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def fake_response(body=b"", chunks=None, status_error=None):
    """Return a mock streamed requests response yielding body or chunks."""
    response = MagicMock()
    response.__enter__.return_value = response
    if status_error:
        response.raise_for_status.side_effect = status_error
    response.raw.read1.side_effect = list(chunks or [body]) + [b""]
    return response


def json_response(obj):
    return fake_response(json.dumps(obj).encode())


def issuer_responses(jwks):
    """Return discovery and JWKS responses for requests.get side_effect."""
    return [json_response({"jwks_uri": JWKS_URI}), json_response(jwks)]


class TestVerifyToken:
    @patch("pia.oidc.requests.get")
    def test_verify_token_success(self, mock_get, private_key):
        """Test token verification."""
        responses = issuer_responses({"keys": [make_jwk(private_key)]})
        mock_get.side_effect = responses

        claims = verify_token(make_token(private_key), ISSUER, AUDIENCE)

        assert claims["iss"] == ISSUER
        assert claims["aud"] == AUDIENCE

        # Assert streamed requests, read in bounded, decoded chunks
        assert mock_get.call_args_list == [
            call(CONFIG_URL, timeout=10, stream=True),
            call(JWKS_URI, timeout=10, stream=True),
        ]
        for response in responses:
            response.raw.read1.assert_called_with(8192, decode_content=True)

    @patch("pia.oidc.requests.get")
    def test_verify_token_oidc_config_fetch_error(self, mock_get):
        """Test error when OIDC config fetch fails."""
        mock_get.side_effect = requests.RequestException()
        with pytest.raises(
            TokenVerificationError, match="Failed to fetch OIDC configuration"
        ):
            verify_token("token", "issuer", "audience")

    @patch("pia.oidc.requests.get")
    def test_verify_token_oidc_config_http_error(self, mock_get):
        """Test error when OIDC config response is an HTTP error."""
        mock_get.return_value = fake_response(status_error=requests.HTTPError("404"))
        with pytest.raises(
            TokenVerificationError, match="Failed to fetch OIDC configuration"
        ):
            verify_token("token", ISSUER, AUDIENCE)

    @patch("pia.oidc.requests.get")
    def test_verify_token_oidc_config_invalid_json(self, mock_get):
        """Test error when OIDC config is not valid JSON."""
        mock_get.return_value = fake_response(b"not json")
        with pytest.raises(
            TokenVerificationError, match="Failed to fetch OIDC configuration"
        ):
            verify_token("token", ISSUER, AUDIENCE)

    @patch("pia.oidc.requests.get")
    def test_verify_token_oidc_config_not_object(self, mock_get):
        """Test error when OIDC config is valid JSON but not an object."""
        mock_get.return_value = json_response(["jwks_uri"])
        with pytest.raises(TokenVerificationError, match="not a JSON object"):
            verify_token("token", ISSUER, AUDIENCE)

    @patch("pia.oidc.requests.get")
    def test_verify_token_missing_jwks_uri(self, mock_get):
        """Test error when OIDC config missing jwks_uri."""
        mock_get.return_value = json_response({})  # missing 'jwks_uri'

        with pytest.raises(TokenVerificationError, match="missing 'jwks_uri'"):
            verify_token("token", "issuer", "audience")

    @patch("pia.oidc.requests.get")
    def test_verify_token_invalid_signature(self, mock_get, private_key):
        """Test token signed by a different key than the published one."""
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        mock_get.side_effect = issuer_responses({"keys": [make_jwk(private_key)]})

        with pytest.raises(TokenVerificationError, match="Signature"):
            verify_token(make_token(other_key), ISSUER, AUDIENCE)

    @patch("pia.oidc.requests.get")
    def test_verify_token_unknown_kid(self, mock_get, private_key):
        """Test error when no published key matches the token's kid."""
        mock_get.side_effect = issuer_responses(
            {"keys": [make_jwk(private_key, kid="other-kid")]}
        )

        with pytest.raises(TokenVerificationError, match="No signing key found"):
            verify_token(make_token(private_key), ISSUER, AUDIENCE)

    @patch("pia.oidc.requests.get")
    def test_verify_token_skips_non_signing_key(self, mock_get, private_key):
        """Test that a key with matching kid but 'enc' use is not selected."""
        mock_get.side_effect = issuer_responses(
            {"keys": [make_jwk(private_key, use="enc")]}
        )

        with pytest.raises(TokenVerificationError, match="No signing key found"):
            verify_token(make_token(private_key), ISSUER, AUDIENCE)

    @patch("pia.oidc.requests.get")
    def test_verify_token_accepts_key_without_use(self, mock_get, private_key):
        """Test that a key without 'use' is selected, like PyJWKClient does."""
        mock_get.side_effect = issuer_responses(
            {"keys": [make_jwk(private_key, use=None)]}
        )

        claims = verify_token(make_token(private_key), ISSUER, AUDIENCE)
        assert claims["iss"] == ISSUER


class TestFetchBounds:
    """Tests for the total deadline and size cap on issuer responses."""

    OVERSIZED_CHUNKS = [b"x" * 8192] * (MAX_RESPONSE_SIZE // 8192 + 10)

    @patch("pia.oidc.requests.get")
    def test_oversized_oidc_config(self, mock_get):
        response = fake_response(chunks=self.OVERSIZED_CHUNKS)
        mock_get.return_value = response

        with pytest.raises(TokenVerificationError, match="exceeds"):
            verify_token("token", ISSUER, AUDIENCE)

        # Stops reading right after the cap is exceeded
        assert response.raw.read1.call_count == MAX_RESPONSE_SIZE // 8192 + 1

    @patch("pia.oidc.requests.get")
    def test_oversized_jwks(self, mock_get, private_key):
        mock_get.side_effect = [
            json_response({"jwks_uri": JWKS_URI}),
            fake_response(chunks=self.OVERSIZED_CHUNKS),
        ]

        with pytest.raises(TokenVerificationError, match="exceeds"):
            verify_token(make_token(private_key), ISSUER, AUDIENCE)

    @patch("pia.oidc.time.monotonic")
    @patch("pia.oidc.requests.get")
    def test_deadline_exceeded(self, mock_get, mock_monotonic):
        # Deadline is set at 0 + TIMEOUT; second chunk arrives after it
        mock_monotonic.side_effect = itertools.chain([0, 5, 11], itertools.repeat(11))
        response = fake_response(chunks=[b"{", b'"jwks_uri"', b": ..."])
        mock_get.return_value = response

        with pytest.raises(TokenVerificationError, match="took longer than 10"):
            verify_token("token", ISSUER, AUDIENCE)

        assert response.raw.read1.call_count == 2


class TestVerifyTokenMetrics:
    """Tests for the OIDC phase timers."""

    @patch("pia.oidc.requests.get")
    def test_records_both_phases(self, mock_get, metric_value, private_key):
        mock_get.side_effect = issuer_responses({"keys": [make_jwk(private_key)]})

        before_discovery = metric_value(
            "pia_oidc_fetch_duration_seconds_count", phase="discovery"
        )
        before_jwks = metric_value(
            "pia_oidc_fetch_duration_seconds_count", phase="jwks"
        )
        before_total = metric_value("pia_token_verification_duration_seconds_count")

        verify_token(make_token(private_key), ISSUER, AUDIENCE)

        assert (
            metric_value("pia_oidc_fetch_duration_seconds_count", phase="discovery")
            == before_discovery + 1
        )
        assert (
            metric_value("pia_oidc_fetch_duration_seconds_count", phase="jwks")
            == before_jwks + 1
        )
        assert (
            metric_value("pia_token_verification_duration_seconds_count")
            == before_total + 1
        )

    @patch("pia.oidc.requests.get")
    def test_failed_discovery_is_still_timed(self, mock_get, metric_value):
        """A failing phase is timed; the phase that never ran is not."""
        mock_get.side_effect = requests.RequestException()

        before_discovery = metric_value(
            "pia_oidc_fetch_duration_seconds_count", phase="discovery"
        )
        before_jwks = metric_value(
            "pia_oidc_fetch_duration_seconds_count", phase="jwks"
        )
        before_total = metric_value("pia_token_verification_duration_seconds_count")

        with pytest.raises(TokenVerificationError):
            verify_token("test.jwt.token", "https://example.com", "test-audience")

        assert (
            metric_value("pia_oidc_fetch_duration_seconds_count", phase="discovery")
            == before_discovery + 1
        )
        assert (
            metric_value("pia_oidc_fetch_duration_seconds_count", phase="jwks")
            == before_jwks
        )
        assert (
            metric_value("pia_token_verification_duration_seconds_count")
            == before_total + 1
        )
