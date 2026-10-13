"""OIDC token validation and signature verification."""

import json
import logging
import time
from typing import Any

import jwt
import requests

from .metrics import OIDC_FETCH_DURATION, TOKEN_VERIFICATION_DURATION

logger = logging.getLogger(__name__)

TIMEOUT = 10
"""Timeout for the OIDC discovery and JWKS requests to the issuer, in seconds.

Verification runs before the caller is authenticated, and each request holds a
threadpool worker for as long as the issuer takes to answer. Used as
connect/read (gap) timeout, and as deadline that is checked between reads of the
response body (see _fetch_json). Neither bounds the total time of a request."""

MAX_RESPONSE_SIZE = 1024 * 1024
"""Maximum size of an OIDC discovery or JWKS response, in bytes (decoded).

Real-world responses are a few KB. The cap bounds the memory an issuer can make
PIA allocate per request."""


class TokenVerificationError(Exception):
    """Raised when token verification fails."""


def _fetch_json(url: str) -> Any:
    """Fetch and parse a JSON document from an issuer, with a size cap.

    The requests timeout is a gap timeout per socket read, so an issuer that
    trickles bytes never trips it. Read the body with read1(), which returns
    after a single socket read of body data, to check the size cap and a
    deadline in between.

    NOTE: This does not prevent slow retrieval. Reads within a single
    requests.get() or read1() call, i.e. of response headers, chunked framing
    (chunk-size lines, extensions, trailers) and the TLS handshake, are bounded
    only per read, so an issuer can trickle them to hold a worker indefinitely
    (see "Future Work" in docs/DESIGN.md).

    Raises TokenVerificationError, requests.RequestException or ValueError.
    """
    deadline = time.monotonic() + TIMEOUT
    with requests.get(url, timeout=TIMEOUT, stream=True) as response:
        response.raise_for_status()
        body = bytearray()
        while chunk := response.raw.read1(8192, decode_content=True):
            body += chunk
            if len(body) > MAX_RESPONSE_SIZE:
                raise TokenVerificationError(
                    f"Response from {url} exceeds {MAX_RESPONSE_SIZE} bytes"
                )
            if time.monotonic() > deadline:
                raise TokenVerificationError(
                    f"Response from {url} took longer than {TIMEOUT} seconds"
                )

    return json.loads(body)


@TOKEN_VERIFICATION_DURATION.time()
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
        logger.debug(f"Fetching OIDC configuration from {config_url!a}")
        with OIDC_FETCH_DURATION.labels(phase="discovery").time():
            oidc_config = _fetch_json(config_url)
        logger.debug("OIDC configuration fetched successfully")

    except (requests.RequestException, ValueError) as e:
        raise TokenVerificationError(
            f"Failed to fetch OIDC configuration from {config_url}: {e}"
        ) from e

    # 2. Extract JWKS URI from issuer configuration
    if not isinstance(oidc_config, dict):
        raise TokenVerificationError("OIDC configuration is not a JSON object")

    jwks_uri = oidc_config.get("jwks_uri")
    if not jwks_uri:
        raise TokenVerificationError("OIDC configuration missing 'jwks_uri'")

    logger.debug(f"JWKS URI: {jwks_uri!a}")

    try:
        # 3. Requests public keys from issuer
        logger.debug("Fetching signing key from JWKS endpoint")
        with OIDC_FETCH_DURATION.labels(phase="jwks").time():
            # Not PyJWKClient, which caps neither size nor total time
            jwk_set = jwt.PyJWKSet.from_dict(_fetch_json(jwks_uri))

        # Same key selection as PyJWKClient
        kid = jwt.get_unverified_header(token).get("kid")
        signing_key = next(
            (
                key
                for key in jwk_set.keys
                if key.key_id
                and key.key_id == kid
                and key.public_key_use in ("sig", None)
            ),
            None,
        )
        if signing_key is None:
            raise TokenVerificationError(f"No signing key found for kid {kid!r}")
        logger.debug("Signing key retrieved successfully")

        # 4. Verify token signature and content
        logger.debug(
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

        logger.debug("Token decoded and verified successfully")
        return claims

    except Exception as e:
        raise TokenVerificationError(e) from e
