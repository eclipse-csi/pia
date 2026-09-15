"""API endpoints for PIA."""

import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated, NoReturn

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from prometheus_client import CONTENT_TYPE_PLAIN_0_0_4, generate_latest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from . import __version__, dependencytrack, metrics, oidc
from .config import Settings
from .metrics import RejectionReason, UploadOutcome
from .models import (
    DependencyTrackUploadPayload,
    PiaUploadPayload,
    PiaUploadResponse,
    Workload,
    find_dt_project,
    find_workload_by_claims,
    is_issuer_known,
    verify_workload_claims,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

ISSUE_TRACKER_URL = "https://github.com/eclipse-csi/pia/issues"
"""Pointer included in rejection responses, so callers can ask for a change."""


# Load settings
settings = Settings()
logger.info("PIA application settings loaded successfully")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database engine and session factory on app startup."""
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_recycle=1800,
    )
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


@app.middleware("http")
async def record_http_metrics(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Count and time every HTTP request, labeled by matched route template."""
    # Default to 500: an unhandled endpoint exception is turned into a 500 by
    # ServerErrorMiddleware, which wraps *outside* this middleware, so here is
    # the only place that outcome can be recorded. Binding it before the `try`
    # (rather than in an `except`) also covers BaseExceptions like the
    # CancelledError raised on client disconnect.
    status_code = 500
    start = time.perf_counter()
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration = time.perf_counter() - start
        # The router writes the matched route into the live scope dict, so it
        # is only readable once the request has been handled.
        route = request.scope.get("route")
        path = route.path if route else metrics.UNMATCHED_PATH
        metrics.HTTP_REQUESTS.labels(
            method=request.method, path=path, status=str(status_code)
        ).inc()
        metrics.HTTP_REQUEST_DURATION.labels(method=request.method, path=path).observe(
            duration
        )


def get_session(request: Request):
    """FastAPI dependency yielding a database session.

    A new Session is created per request and closed when the request finishes.
    """
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def _401(msg: str, reason: RejectionReason) -> NoReturn:
    """Count the rejection and return 401.

    The `reason` label is typed as a Literal so mypy rejects any value outside
    the declared set, keeping the metric's cardinality bounded by construction.
    """
    metrics.UPLOAD_REJECTIONS.labels(reason=reason).inc()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=msg,
    )


def _record_upload(
    workload: Workload,
    product_name: str,
    outcome: UploadOutcome,
) -> None:
    """Count an upload attempt for an authenticated workload."""
    metrics.SBOM_UPLOADS.labels(
        ef_project_id=workload.ef_project_id,
        product_name=product_name,
        outcome=outcome,
    ).inc()


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
        _401("Invalid Authorization header format", "invalid_header")
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
        _401("Invalid token", "invalid_token")

    logger.info(f"Unverified issuer extracted: {unverified_issuer!a}")

    # Pre-verification check. The issuer URL from the unverified token is used
    # for OIDC discovery and JWKs requests. It MUST NOT be chosen freely by an
    # untrusted caller (CWE-918).
    # NOTE: Issuers that look like Jenkins are matched against registered
    # Jenkins workloads in the DB. This may be more costly than a pattern
    # match, but cannot be bypassed.
    if not is_issuer_known(session, unverified_issuer):
        logger.warning(f"Issuer {unverified_issuer!a} not allowed")
        _401("Issuer not allowed", "issuer_not_allowed")

    logger.info(
        f"Issuer '{unverified_issuer!a}' is allowed, proceeding with token verification"
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
        _401("Token verification failed", "verification_failed")

    logger.info("Token signature verified successfully")

    # Find workload by matching verified claims
    workload = find_workload_by_claims(session, verified_claims)
    if not workload:
        logger.warning(
            f"No matching workload found for token claims: {verified_claims}"
        )
        _401("No matching workload found for token claims", "no_workload")

    # Workload-type-specific claim verification (e.g. GitHub event_name allowlist)
    reason = verify_workload_claims(workload, verified_claims)
    if reason:
        logger.warning(f"Token claims rejected: {reason}")
        # Include reason in response: at this point the caller is a registered
        # workload holding a verified token, and it needs to know which claim
        # was rejected to fix its workflow (or submit an issue).
        _401(
            f"Token claims rejected: {reason}. If this claim should be "
            f"accepted, file an issue at {ISSUE_TRACKER_URL}",
            "claims_rejected",
        )

    logger.info(
        f"Authenticated workload (project={workload.ef_project_id}, "
        f"type={workload.type}, id={workload.id})"
    )

    return workload


@app.get("/livez")
async def livez():
    """Kubernetes liveness probe."""
    return {"status": "ok"}


@app.get("/metrics")
async def get_metrics():
    """Prometheus scrape endpoint.

    Pins the 0.0.4 text format: prometheus_client's CONTENT_TYPE_LATEST now
    advertises version=1.0.0, and the scraper version is set by the Helm chart,
    not by us.
    """
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_PLAIN_0_0_4,
    )


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
        # The requested product_name is caller-controlled and unvalidated at
        # this point, so it must not become a label value.
        _record_upload(workload, metrics.UNREGISTERED_PRODUCT, "no_dt_project")
        _401("No matching DependencyTrack project found", "no_dt_project")

    logger.info(
        f"Resolved DependencyTrack project '{dt_project.name}' "
        f"(parent_uuid={dt_project.parent_uuid})"
    )

    # payload.bom is base64; derive the decoded size arithmetically rather than
    # decoding a multi-MB string just to measure it. Observed before the upload
    # so the size is recorded even when DependencyTrack rejects it.
    metrics.SBOM_SIZE.observe(len(payload.bom) * 3 // 4)

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
        with metrics.DT_UPLOAD_DURATION.time():
            dt_response = dependencytrack.upload_sbom(
                str(settings.dependency_track_url),
                settings.dependency_track_api_key,
                dt_payload,
            )
    except dependencytrack.DependencyTrackError as e:
        logger.error(f"DependencyTrack upload failed: {e}")
        _record_upload(workload, dt_project.name, "dt_request_error")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to upload to DependencyTrack",
        ) from e

    # Relay DT failures verbatim; on success, return the polling URL the
    # publisher should query for processing status.
    if not dt_response.ok:
        _record_upload(workload, dt_project.name, "dt_http_error")
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
        _record_upload(workload, dt_project.name, "dt_bad_response")
        raise

    _record_upload(workload, dt_project.name, "success")

    dt_url = str(settings.dependency_track_url).rstrip("/")
    return PiaUploadResponse(
        polling_url=f"{dt_url}/token/{token}",  # type: ignore[arg-type]
    )
