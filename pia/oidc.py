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
) -> dict[str, Any]:
    """Verify JWT token signature using OIDC discovery and return claims.
    Raises TokenVerificationError, if verification fails
    """
    # 1. Request OIDC configuration from issuer
    config_url = f"{issuer}/.well-known/openid-configuration"

    try:
        response = requests.get(config_url, timeout=10)
        response.raise_for_status()
        oidc_config = response.json()

    except requests.RequestException as e:
        raise TokenVerificationError(
            f"Failed to fetch OIDC configuration from {config_url}: {e}"
        ) from e

    # 2. Extract JWKS URI from issuer configuration
    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri:
        raise TokenVerificationError("OIDC configuration missing 'jwks_uri'")

    try:
        # 3. Requests public keys from issuer
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # 4. Verify token signature and content
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
                require={"aud", "exp", "iat"},
            ),
        )

        return claims

    except Exception as e:
        raise TokenVerificationError(e) from e
