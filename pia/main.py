"""API endpoints for PIA."""

import logging
from contextlib import asynccontextmanager

import jwt
from fastapi import FastAPI, HTTPException, Request, Response, status
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
async def upload_sbom(payload: PiaUploadPayload, request: Request):
    """Handle SBOM upload with OIDC authentication.

    Implements authentication flow from DESIGN.md section 3.1.1.
    """
    projects: Projects = request.app.state.projects
    project_id: str = payload.project_id

    # Verify project is allowed
    project = projects.find_project(project_id)
    if not project:
        logger.warning(f"Unknown project: {project_id}")
        _401("Project not allowed")

    # Extract issuer from unverified token
    try:
        unverified_claims = jwt.decode(
            payload.token,
            options=dict(verify_signature=False, require=["iss"]),
        )
        unverified_issuer: str = unverified_claims["iss"]
    except jwt.PyJWTError as e:
        logger.warning(f"Token decode failed: {e}")
        _401("Invalid token")

    # Since we already have the issuer, we might as well check, if it is
    # allowed, to fail early, before fetching keys, etc. Note that we can only
    # trust an allowed issuer after having verified the token below.
    if not project.match_issuer(unverified_issuer):
        logger.warning(
            f"Issuer {unverified_issuer} not allowed for project {project_id}"
        )
        _401("Issuer not allowed")

    # Full token verification
    try:
        verified_claims = oidc.verify_token(
            payload.token,
            unverified_issuer,
            settings.expected_audience,
            set(project.required_claims.keys()),
        )
    except oidc.TokenVerificationError as e:
        logger.warning(f"Token verification failed: {e}")
        _401("Token verification failed")

    # Project authentication
    if not project.match_claims(verified_claims):
        logger.warning(f"Token claims mismatch for project {project_id}")
        _401("Project token claim mismatch")

    logger.info(
        f"Successfully authenticated project {project_id} "
        f"with issuer {verified_claims['iss']}"
    )

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
            f"Uploaded SBOM for {payload.project_id}/{payload.product_name} "
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
