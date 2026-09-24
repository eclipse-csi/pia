"""Prometheus metric definitions.

Metrics live in the default process-global registry and are exposed at
``GET /metrics``. This assumes ONE uvicorn worker per container (see the
Dockerfile CMD); running with ``--workers`` would need prometheus_client's
multiprocess mode.
"""

from typing import Literal

from prometheus_client import Counter, Histogram, Info
from prometheus_client.utils import INF

from . import __version__

RejectionReason = Literal[
    "invalid_header",
    "invalid_token",
    "issuer_not_allowed",
    "verification_failed",
    "no_workload",
    "claims_rejected",
    "no_dt_project",
]
"""Allowed ``reason`` label values for `UPLOAD_REJECTIONS`.

Typing this as a Literal is what keeps the label bounded: mypy rejects any
value not listed here, so a new rejection path cannot silently widen the
metric's cardinality.
"""

UploadOutcome = Literal[
    "success",
    "no_dt_project",
    "dt_request_error",
    "dt_http_error",
    "dt_bad_response",
]
"""Allowed ``outcome`` label values for `SBOM_UPLOADS`."""

UNMATCHED_PATH = "<unmatched>"
"""``path`` label for requests that matched no route.

Route templates always start with "/", so this cannot collide with one."""

DISCONNECTED_STATUS = "<disconnected>"
"""``status`` label for requests that produced no response.

Keeps a client that hangs up mid-request out of the 5xx rate, which would
otherwise page on a purely client-side abort."""

OTHER_METHOD = "<other>"
"""``method`` label for requests using a non-standard HTTP method.

Method tokens cannot contain "<", so this cannot collide with one."""

HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"}
)
"""The standard HTTP methods, per RFC 9110 plus PATCH."""


def method_label(method: str) -> str:
    """Bound the ``method`` label to `HTTP_METHODS`.

    The request method reaches the middleware before any routing or method
    validation, and the HTTP parser accepts any token as a method, so the raw
    value is caller-controlled and unbounded: without this, anyone can mint
    permanent series with a single unauthenticated request.
    """
    return method if method in HTTP_METHODS else OTHER_METHOD


UNREGISTERED_PRODUCT = "_unregistered"
"""``product_name`` label for uploads rejected before the name was resolved.

The requested name is caller-controlled and therefore unbounded; it must never
reach a label."""

NETWORK_BUCKETS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, INF)
"""Buckets for every latency in PIA.

All of them are dominated by blocking calls to external services (OIDC
discovery, JWKS, DependencyTrack), so the default sub-25ms buckets are dead
weight and the default 10s ceiling is too low: the OIDC discovery timeout alone
is 10s, PyJWT's JWKS fetch defaults to 30s, and DependencyTrack's 30s read
timeout bounds silence between bytes rather than the whole request, so a slow
multi-MB upload can outlast it."""

SBOM_SIZE_BUCKETS = (1e4, 1e5, 1e6, 5e6, 1e7, 5e7, INF)

HTTP_REQUESTS = Counter(
    "pia_http_requests_total",
    "HTTP requests by method, matched route template, and response status.",
    ["method", "path", "status"],
)

HTTP_REQUEST_DURATION = Histogram(
    "pia_http_request_duration_seconds",
    "Total time to produce an HTTP response.",
    ["method", "path"],
    buckets=NETWORK_BUCKETS,
)

UPLOAD_REJECTIONS = Counter(
    "pia_upload_rejections_total",
    "SBOM uploads rejected with 401, by reason.",
    ["reason"],
)

TOKEN_VERIFICATION_DURATION = Histogram(
    "pia_token_verification_duration_seconds",
    "Time spent in full OIDC token verification, including failures.",
    buckets=NETWORK_BUCKETS,
)

OIDC_FETCH_DURATION = Histogram(
    "pia_oidc_fetch_duration_seconds",
    "Time spent fetching issuer metadata, by phase.",
    ["phase"],
    buckets=NETWORK_BUCKETS,
)

DT_UPLOAD_DURATION = Histogram(
    "pia_dependencytrack_upload_duration_seconds",
    "Time spent in the DependencyTrack upload request, including failures.",
    buckets=NETWORK_BUCKETS,
)

SBOM_UPLOADS = Counter(
    "pia_sbom_uploads_total",
    "SBOM uploads by Eclipse Foundation project, product, and outcome.",
    ["ef_project_id", "product_name", "outcome"],
)

SBOM_SIZE = Histogram(
    "pia_sbom_size_bytes",
    "Decoded size of uploaded SBOMs.",
    buckets=SBOM_SIZE_BUCKETS,
)

# Exposed as `pia_build_info`; Info appends the `_info` suffix itself.
BUILD = Info("pia_build", "PIA build information.")
BUILD.info({"version": __version__})
