"""OIDC token validation and signature verification."""

import logging
from typing import Any

import jwt
import requests

logger = logging.getLogger(__name__)


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
    logger.info(f"Starting token verification for issuer: {issuer}")

    # 1. Request OIDC configuration from issuer
    config_url = f"{issuer}/.well-known/openid-configuration"

    try:
        logger.info(f"Fetching OIDC configuration from {config_url}")
        response = requests.get(config_url, timeout=10)
        response.raise_for_status()
        oidc_config = response.json()
        logger.info("OIDC configuration fetched successfully")

    except requests.RequestException as e:
        raise TokenVerificationError(
            f"Failed to fetch OIDC configuration from {config_url}: {e}"
        ) from e

    # 2. Extract JWKS URI from issuer configuration
    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri:
        raise TokenVerificationError("OIDC configuration missing 'jwks_uri'")

    logger.info(f"JWKS URI: {jwks_uri}")

    try:
        # 3. Requests public keys from issuer
        logger.info("Fetching signing key from JWKS endpoint")
        jwks_client = jwt.PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        logger.info("Signing key retrieved successfully")

        # 4. Verify token signature and content
        logger.info(
            f"Verifying token signature and claims "
            f"(expected audience: {expected_audience})"
        )
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
                require=["aud", "exp", "iat"],
            ),
        )

        logger.info("Token decoded and verified successfully")
        return claims

    except Exception as e:
        raise TokenVerificationError(e) from e
