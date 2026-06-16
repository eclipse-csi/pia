"""API endpoints for PIA."""

import logging
from contextlib import asynccontextmanager
from typing import Annotated, NoReturn

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from . import __version__, dependencytrack, oidc
from .config import Settings
from .models import (
    DependencyTrackUploadPayload,
    PiaUploadPayload,
    PiaUploadResponse,
    Workload,
    find_dt_project,
    find_workload_by_claims,
    is_issuer_known,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# Load settings
settings = Settings()
logger.info("PIA application settings loaded successfully")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database engine and session factory on app startup."""
    engine = create_engine(settings.database_url)
    app.state.session_factory = sessionmaker(bind=engine)
    logger.info("Database engine and session factory initialized")
    yield
    # Release pooled connections at shutdown.
    engine.dispose()


# Create app
app = FastAPI(
    title="Project Identity Authority (PIA)",
    description="OIDC-based authentication broker for Eclipse Foundation projects",
    version=__version__,
    lifespan=lifespan,
)
logger.info("PIA application initialized successfully")


def get_session(request: Request):
    """FastAPI dependency yielding a database session.

    A new Session is created per request and closed when the request finishes.
    """
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def _401(msg: str) -> NoReturn:
    """Helper to return 401"""
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=msg,
    )


async def authenticate(
    authorization: Annotated[str, Header()],
    session: Annotated[Session, Depends(get_session)],
) -> Workload:
    """Authenticate request via OIDC Bearer token, return matched Workload.

    Implements authentication flow from DESIGN.md section 3.1.1.
    Token must be provided as Bearer token in Authorization header (RFC6750).
    """
    logger.info("Received SBOM upload request")

    # Extract Bearer token from Authorization header
    if not authorization.startswith("Bearer "):
        _401("Invalid Authorization header format")
    token = authorization[7:]  # Remove "Bearer " prefix

    logger.info("Bearer token extracted from Authorization header")

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

    logger.info(f"Unverified issuer extracted: {unverified_issuer}")

    # Inexpensive pre-verification check
    if not is_issuer_known(unverified_issuer):
        logger.warning(f"Issuer {unverified_issuer} not allowed")
        _401("Issuer not allowed")

    logger.info(
        f"Issuer '{unverified_issuer}' is allowed, proceeding with token verification"
    )
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

    logger.info("Token signature verified successfully")

    # Find workload by matching verified claims
    workload = find_workload_by_claims(session, verified_claims)
    if not workload:
        logger.warning(
            f"No matching workload found for token claims: {verified_claims}"
        )
        _401("No matching workload found for token claims")

    logger.info(
        f"Authenticated workload (project={workload.ef_project_id}, "
        f"type={workload.type}, id={workload.id})"
    )

    return workload


@app.get("/livez")
async def livez():
    """Kubernetes liveness probe."""
    return {"status": "ok"}


@app.post("/v1/upload/sbom", status_code=status.HTTP_200_OK)
async def upload_sbom(
    payload: PiaUploadPayload,
    workload: Annotated[Workload, Depends(authenticate)],
    session: Annotated[Session, Depends(get_session)],
):
    """Handle SBOM upload."""
    # Resolve DependencyTrack project (must share workload's ef_project_id)
    dt_project = find_dt_project(session, workload.ef_project_id, payload.product_name)
    if not dt_project:
        logger.warning(
            f"No DependencyTrack project '{payload.product_name}' found for "
            f"ef_project_id '{workload.ef_project_id}'"
        )
        _401("No matching DependencyTrack project found")

    logger.info(
        f"Resolved DependencyTrack project '{dt_project.name}' "
        f"(parent_uuid={dt_project.parent_uuid})"
    )

    # Build DependencyTrack payload
    dt_payload = DependencyTrackUploadPayload(
        project_name=payload.product_name,
        project_version=payload.product_version,
        parent_uuid=dt_project.parent_uuid,
        is_latest=payload.is_latest,
        bom=payload.bom,
    )

    # Upload to DependencyTrack
    try:
        dt_response = dependencytrack.upload_sbom(
            str(settings.dependency_track_url),
            settings.dependency_track_api_key,
            dt_payload,
        )
    except dependencytrack.DependencyTrackError as e:
        logger.error(f"DependencyTrack upload failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to upload to DependencyTrack",
        ) from e

    # Relay DT failures verbatim; on success, return the polling URL the
    # publisher should query for processing status.
    if not dt_response.ok:
        return Response(
            content=dt_response.content,
            status_code=dt_response.status_code,
            media_type="application/json",
        )

    try:
        token = dt_response.json()["token"]
    except (ValueError, KeyError):
        # DT returned a 2xx with an unexpected body shape — the upload
        # likely landed, but we can't hand the publisher a polling URL.
        # Log full context and re-raise so FastAPI returns 500: a retry
        # is NOT safe (it would duplicate the SBOM in DT).
        logger.error(
            f"DependencyTrack returned unparseable success response "
            f"(status={dt_response.status_code}, body={dt_response.text!r})"
        )
        raise

    dt_url = str(settings.dependency_track_url).rstrip("/")
    return PiaUploadResponse(
        polling_url=f"{dt_url}/token/{token}",  # type: ignore[arg-type]
    )
