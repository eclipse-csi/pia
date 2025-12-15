"""OIDC token validation and signature verification."""

from typing import Any

import jwt
import requests


class TokenVerificationError(Exception):
    """Raised when token verification fails."""


def verify_token(
    token: str,
    issuer: str,
    expected_audience: str,
    required_claims: set,
) -> dict[str, Any]:
    """Verify JWT token signature using OIDC discovery.

    This performs full cryptographic verification:
    1. Fetches OIDC configuration from issuer
    2. Gets JWKS URI from configuration
    3. Fetches public keys using PyJWKClient
    4. Verifies signature using RS256
    5. Validates token schema

    Args:
        token: JWT token string
        issuer: Expected issuer URL
        expected_audience: Expected audience value

    Returns:
        Fully verified token claims

    Raises:
        TokenVerificationError: If signature verification fails
    """
    # Fetch OIDC configuration
    config_url = f"{issuer}/.well-known/openid-configuration"

    try:
        response = requests.get(config_url, timeout=10)
        response.raise_for_status()
        oidc_config = response.json()

    except requests.RequestException as e:
        raise TokenVerificationError(
            f"Failed to fetch OIDC configuration from {config_url}: {e}"
        ) from e

    # Extract JWKS URI
    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri:
        raise TokenVerificationError("OIDC configuration missing 'jwks_uri'")

    try:
        # Create PyJWKClient to fetch signing keys
        jwks_client = jwt.PyJWKClient(jwks_uri)

        # Get signing key from token
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Verify token with full validation
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=expected_audience,
            options=dict(
                verify_signature=True,
                verify_exp=True,
                verify_aud=True,
                verify_iat=True,
                require={"aud", "exp", "iat"} | required_claims,
            ),
        )

        return claims

    except Exception as e:
        raise TokenVerificationError(e) from e
