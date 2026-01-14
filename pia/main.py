"""API endpoints for PIA."""

import logging
from contextlib import asynccontextmanager
from typing import Annotated

import jwt
from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import __version__, dependencytrack, oidc
from .models import (
    DependencyTrackUploadPayload,
    PiaUploadPayload,
    Projects,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Define settings
class Settings(BaseSettings):
    """Application settings loaded from environment variables

    e.g. PIA_DEPENDENCY_TRACK_API_KEY -> dependency_track_api_key
    """

    dependency_track_api_key: str
    """
    DependencyTrack API Key
    https://docs.dependencytrack.org/integrations/rest-api/
    """
    projects_path: str
    """
    Path to projects.yaml
    """

    expected_audience: str = "pia.eclipse.org"
    """
    Expected value for "aud" claim in all OIDC tokens
    """

    dependency_track_url: HttpUrl = "https://sbom.eclipse.org/api/v1/bom"
    """
    DependencyTrack SBOM upload URL
    """

    model_config = SettingsConfigDict(env_prefix="PIA_", use_attribute_docstrings=True)


# Load settings
settings = Settings()
logger.info("PIA application settings loaded successfully")


# Lifespan wrapper to load projects from file only once on app startup
# see https://fastapi.tiangolo.com/advanced/events/
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.projects = Projects.from_yaml_file(settings.projects_path)
    logger.info(f"Loaded projects from {settings.projects_path}")
    yield


# Create app
app = FastAPI(
    title="Project Identity Authority (PIA)",
    description="OIDC-based authentication broker for Eclipse Foundation projects",
    version=__version__,
    lifespan=lifespan,
)
logger.info("PIA application initialized successfully")


def _401(msg: str):
    """Helper to return 401"""
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=msg,
    )


@app.post("/v1/upload/sbom", status_code=status.HTTP_200_OK)
async def upload_sbom(
    payload: PiaUploadPayload,
    request: Request,
    authorization: Annotated[str, Header()],
):
    """Handle SBOM upload with OIDC authentication.

    Implements authentication flow from DESIGN.md section 3.1.1.
    Token must be provided as Bearer token in Authorization header (RFC6750).
    """
    # ==========================================================================
    # Handle Auth Header
    projects: Projects = request.app.state.projects

    # Extract Bearer token from Authorization header
    if not authorization.startswith("Bearer "):
        _401("Invalid Authorization header format")
    token = authorization[7:]  # Remove "Bearer " prefix

    # Extract issuer from unverified token
    try:
        unverified_claims = jwt.decode(
            token,
            options=dict(verify_signature=False, require=["iss"]),
        )
        unverified_issuer: str = unverified_claims["iss"]
    except jwt.PyJWTError as e:
        logger.warning(f"Token decode failed: {e}")
        _401("Invalid token")

    # Check if issuer exists in any project configuration to fail early
    #
    # NOTE: This is an expensive operation (iterates over all projects) for a
    # completely unauthenticated request. Consider to ...
    # - make less expensive (optimize with db), or
    # - match against issuer constants (full for GitHub, prefix-only for Jenkins)
    if not projects.has_issuer(unverified_issuer):
        logger.warning(f"Issuer {unverified_issuer} not allowed")
        _401("Issuer not allowed")

    # Full token verification
    try:
        verified_claims = oidc.verify_token(
            token,
            unverified_issuer,
            settings.expected_audience,
        )
    except oidc.TokenVerificationError as e:
        logger.warning(f"Token verification failed: {e}")
        _401("Token verification failed")

    # Find project by matching verified token claims
    # NOTE: Returns first match
    project = projects.find_project_by_claims(verified_claims)
    if not project:
        logger.warning(f"No matching project found for token claims: {verified_claims}")
        _401("No matching project found for token claims")

    logger.info(
        f"Successfully authenticated project {project.project_id} "
        f"with issuer {verified_claims['iss']}"
    )

    # ==========================================================================
    # Handle Payload

    # Create DependencyTrack payload
    dt_payload = DependencyTrackUploadPayload(
        project_name=payload.product_name,
        project_version=payload.product_version,
        parent_uuid=project.dt_parent_uuid,
        bom=payload.bom,
    )

    # Upload to DependencyTrack
    try:
        dt_response = dependencytrack.upload_sbom(
            str(settings.dependency_track_url),
            settings.dependency_track_api_key,
            dt_payload,
        )
        logger.info(
            f"Uploaded SBOM for {project.project_id}/{payload.product_name} "
            f"to DependencyTrack (status: {dt_response.status_code})"
        )

        # Relay DependencyTrack response
        response = Response(
            content=dt_response.content,
            status_code=dt_response.status_code,
            media_type="application/json",
        )
        return response

    except dependencytrack.DependencyTrackError as e:
        logger.error(f"DependencyTrack upload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to upload to DependencyTrack",
        ) from e
