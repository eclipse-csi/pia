"""Tests for api module."""

import asyncio
import logging
from unittest.mock import Mock, patch

import jwt
import pytest
from fastapi import HTTPException, Request
from prometheus_client import REGISTRY
from starlette.requests import ClientDisconnect

from pia import metrics
from pia.dependencytrack import DependencyTrackError
from pia.models import GitHubWorkload, Workload
from pia.oidc import TokenVerificationError

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
BEARER_TOKEN = "Bearer eyJhbGciOiJSUzI1NiJ9.test.token"


@pytest.fixture
def valid_request_data():
    """Valid request data for SBOM upload."""
    return {
        "product_name": "test-product",
        "product_version": "1.0.0",
        "bom": "bom",
    }


@pytest.fixture
def authenticate_as_workload(seed_db):
    """Bypass authentication, returning a fixed Workload from the seeded DB."""
    from pia.main import app, authenticate

    workload = (
        seed_db.query(GitHubWorkload).filter_by(ef_project_id="eclipse-test").one()
    )

    app.dependency_overrides[authenticate] = lambda: workload
    yield
    app.dependency_overrides.clear()


@pytest.mark.usefixtures("setup_env")
class TestAuthenticate:
    """Tests for the authenticate dependency, called as a regular function."""

    def _call(self, authorization, session):
        from pia.main import authenticate

        return asyncio.run(authenticate(authorization, session))

    def test_invalid_authorization_header(self, seed_db):
        """Error when Authorization header doesn't start with 'Bearer '."""
        with pytest.raises(HTTPException) as exc:
            self._call("Basic invalid", seed_db)
        assert exc.value.status_code == 401
        assert "Invalid Authorization header format" in exc.value.detail

    @patch("pia.main.jwt.decode")
    def test_token_decode_fails(self, mock_decode, seed_db):
        """Error when initial token decode fails."""
        mock_decode.side_effect = jwt.PyJWTError()
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, seed_db)
        assert exc.value.status_code == 401
        assert "Invalid token" in exc.value.detail

    @patch("pia.main.jwt.decode")
    def test_issuer_not_allowed(self, mock_decode, seed_db):
        """Error when issuer is not registered with any workload."""
        mock_decode.return_value = {"iss": "https://wrong-issuer.com"}
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, seed_db)
        assert exc.value.status_code == 401
        assert "Issuer not allowed" in exc.value.detail

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_token_verification_fails(self, mock_decode, mock_verify, seed_db):
        """Error when token signature verification fails."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.side_effect = TokenVerificationError()
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, seed_db)
        assert exc.value.status_code == 401
        assert "Token verification failed" in exc.value.detail

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_no_matching_workload(self, mock_decode, mock_verify, seed_db):
        """Error when no workload matches the verified token claims."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/wrong-repo",
            "repository_owner_id": "42",
        }
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, seed_db)
        assert exc.value.status_code == 401
        assert "No matching workload found" in exc.value.detail

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_success(self, mock_decode, mock_verify, seed_db):
        """Successful authentication returns the matched Workload."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/repo",
            "repository_owner_id": "42",
            "event_name": "push",
        }
        result = self._call(BEARER_TOKEN, seed_db)
        assert isinstance(result, Workload)
        assert result.ef_project_id == "eclipse-test"

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_github_disallowed_event_name(self, mock_decode, mock_verify, seed_db):
        """GitHub token with disallowed event_name is rejected."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/repo",
            "repository_owner_id": "42",
            "event_name": "pull_request_target",
        }
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, seed_db)
        assert exc.value.status_code == 401
        assert "Token claims rejected" in exc.value.detail
        # The rejected claim and the allowlist are echoed back, so the caller
        # can fix its workflow or ask for the allowlist to be extended.
        assert "pull_request_target" in exc.value.detail
        assert "workflow_dispatch" in exc.value.detail
        assert "github.com/eclipse-csi/pia/issues" in exc.value.detail

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_github_missing_event_name(self, mock_decode, mock_verify, seed_db):
        """GitHub token without an event_name claim is rejected."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/repo",
            "repository_owner_id": "42",
        }
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, seed_db)
        assert exc.value.status_code == 401
        assert "Token claims rejected" in exc.value.detail


class TestUploadSBOMEndpoint:
    """Tests for /v1/upload/sbom endpoint, with authentication bypassed."""

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_upload_success(
        self,
        mock_upload,
        client,
        valid_request_data,
        authenticate_as_workload,
    ):
        """Successful SBOM upload returns DT polling URL."""
        mock_dt_response = Mock()
        mock_dt_response.ok = True
        mock_dt_response.status_code = 200
        mock_dt_response.json.return_value = {"token": "dt-token-abc"}
        mock_upload.return_value = mock_dt_response

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 200
        assert response.json() == {
            "polling_url": "https://sbom.eclipse.org/api/v1/bom/token/dt-token-abc"
        }

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_upload_dt_malformed_success_body(
        self,
        mock_upload,
        client,
        valid_request_data,
        authenticate_as_workload,
        caplog,
    ):
        """A 2xx DT response without a 'token' field propagates an error.

        TestClient re-raises server exceptions; in production FastAPI's ASGI
        server converts them to 500. Either way the publisher does not get
        a misleading 200.
        """
        mock_dt_response = Mock()
        mock_dt_response.ok = True
        mock_dt_response.status_code = 200
        mock_dt_response.json.return_value = {"unexpected": "shape"}
        mock_dt_response.text = '{"unexpected": "shape"}'
        mock_upload.return_value = mock_dt_response

        with pytest.raises(KeyError):
            client.post("/v1/upload/sbom", json=valid_request_data)

        assert "unparseable success response" in caplog.text
        assert "unexpected" in caplog.text

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_upload_dt_non_ok_relayed(
        self,
        mock_upload,
        client,
        valid_request_data,
        authenticate_as_workload,
    ):
        """Non-2xx DT responses are relayed verbatim, not wrapped."""
        mock_dt_response = Mock()
        mock_dt_response.ok = False
        mock_dt_response.status_code = 400
        mock_dt_response.content = b'{"detail":"invalid bom"}'
        mock_upload.return_value = mock_dt_response

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 400
        assert response.content == b'{"detail":"invalid bom"}'

    def test_upload_invalid_json(self, client, authenticate_as_workload):
        """Error with invalid JSON."""
        response = client.post("/v1/upload/sbom", content=b"not-json")
        assert response.status_code == 422
        assert b"JSON" in response.content or b"json" in response.content

    def test_upload_missing_field(
        self, client, valid_request_data, authenticate_as_workload
    ):
        """Error with missing required field."""
        del valid_request_data["product_name"]
        response = client.post("/v1/upload/sbom", json=valid_request_data)
        assert response.status_code == 422
        assert b"product_name" in response.content

    def test_upload_no_matching_dt_project(
        self, client, valid_request_data, authenticate_as_workload
    ):
        """Error when product_name doesn't match any DependencyTrack project."""
        valid_request_data["product_name"] = "unknown-product"
        response = client.post("/v1/upload/sbom", json=valid_request_data)
        assert response.status_code == 401
        assert b"No matching DependencyTrack project found" in response.content

    def test_upload_dt_project_in_other_ef_project(
        self, client, valid_request_data, authenticate_as_workload
    ):
        """The DT project must share the workload's ef_project_id."""
        # 'other-product' exists only under 'eclipse-other', but the workload
        # is under 'eclipse-test'.
        valid_request_data["product_name"] = "other-product"
        response = client.post("/v1/upload/sbom", json=valid_request_data)
        assert response.status_code == 401
        assert b"No matching DependencyTrack project found" in response.content

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_upload_dt_error(
        self,
        mock_upload,
        client,
        valid_request_data,
        authenticate_as_workload,
    ):
        """Error when DependencyTrack upload fails."""
        mock_upload.side_effect = DependencyTrackError()
        response = client.post("/v1/upload/sbom", json=valid_request_data)
        assert response.status_code == 502
        assert b"Failed to upload to DependencyTrack" in response.content


class TestHealthEndpoints:
    """Tests for k8s health endpoints."""

    def test_liveness(self, client):
        response = client.get("/livez")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.usefixtures("setup_env")
class TestNewlineEscaping:
    """Regression for escaping newlines when logging unverified JWT `iss`."""

    @patch("pia.main.jwt.decode")
    def test_newline_in_unverified_iss_does_not_split_records(
        self, mock_decode, seed_db, caplog
    ):
        from pia.main import authenticate

        forged_iss = (
            "https://x.example\n"
            "2026-04-27 09:00:00,000 - pia.main - INFO - forged record"
        )
        mock_decode.return_value = {"iss": forged_iss}

        with (
            caplog.at_level(logging.INFO, logger="pia.main"),
            pytest.raises(HTTPException),
        ):
            asyncio.run(authenticate(BEARER_TOKEN, seed_db))

        for record in caplog.records:
            msg = record.getMessage()
            assert "\n" not in msg, f"newline leaked into: {msg!r}"
        assert any("\\n" in r.getMessage() for r in caplog.records), (
            "expected escaped newline somewhere in captured logs"
        )


@pytest.mark.usefixtures("setup_env", "authenticate_as_workload")
class TestHTTPMetrics:
    """Tests for the request-counting middleware."""

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_success_labeled_with_route_template(
        self, mock_upload, client, valid_request_data, metric_value
    ):
        mock_dt_response = Mock()
        mock_dt_response.ok = True
        mock_dt_response.status_code = 200
        mock_dt_response.json.return_value = {"token": "dt-token-abc"}
        mock_upload.return_value = mock_dt_response

        labels = dict(method="POST", path="/v1/upload/sbom", status="200")
        before = metric_value("pia_http_requests_total", **labels)
        before_duration = metric_value(
            "pia_http_request_duration_seconds_count",
            method="POST",
            path="/v1/upload/sbom",
        )

        client.post("/v1/upload/sbom", json=valid_request_data)

        assert metric_value("pia_http_requests_total", **labels) == before + 1
        assert (
            metric_value(
                "pia_http_request_duration_seconds_count",
                method="POST",
                path="/v1/upload/sbom",
            )
            == before_duration + 1
        )

    def test_unmatched_paths_collapse_to_sentinel(self, client, metric_value):
        """Unrouted paths must not mint a label value each (cardinality)."""
        labels = dict(method="GET", path="<unmatched>", status="404")
        before = metric_value("pia_http_requests_total", **labels)

        client.get("/v1/nope/aaa")
        client.get("/v1/nope/bbb")

        assert metric_value("pia_http_requests_total", **labels) == before + 2
        for raw in ("/v1/nope/aaa", "/v1/nope/bbb"):
            assert (
                metric_value(
                    "pia_http_requests_total", method="GET", path=raw, status="404"
                )
                == 0.0
            )

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_relayed_dt_status_is_counted_verbatim(
        self, mock_upload, client, valid_request_data, metric_value
    ):
        """The raw DT relay Response must be counted as DT's status, not 200."""
        mock_dt_response = Mock()
        mock_dt_response.ok = False
        mock_dt_response.status_code = 400
        mock_dt_response.content = b'{"detail":"invalid bom"}'
        mock_upload.return_value = mock_dt_response

        labels = dict(method="POST", path="/v1/upload/sbom")
        before_400 = metric_value("pia_http_requests_total", **labels, status="400")
        before_200 = metric_value("pia_http_requests_total", **labels, status="200")

        client.post("/v1/upload/sbom", json=valid_request_data)

        assert metric_value("pia_http_requests_total", **labels, status="400") == (
            before_400 + 1
        )
        assert metric_value("pia_http_requests_total", **labels, status="200") == (
            before_200
        )

    def test_nonstandard_methods_collapse_to_sentinel(self, client, metric_value):
        """Invented methods must not mint a label value each (cardinality)."""
        labels = dict(method=metrics.OTHER_METHOD, path="/livez", status="405")
        before = metric_value("pia_http_requests_total", **labels)

        client.request("XYZZY", "/livez")
        client.request("PWNME", "/livez")

        assert metric_value("pia_http_requests_total", **labels) == before + 2
        recorded = {
            sample.labels["method"]
            for metric in REGISTRY.collect()
            for sample in metric.samples
            if "method" in sample.labels
        }
        assert recorded <= metrics.HTTP_METHODS | {metrics.OTHER_METHOD}

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_client_disconnect_is_not_counted_as_500(
        self, mock_upload, client, valid_request_data, metric_value
    ):
        """A hangup must stay out of the 5xx rate an SLO alert watches."""
        mock_upload.side_effect = ClientDisconnect
        labels = dict(method="POST", path="/v1/upload/sbom")
        before_500 = metric_value("pia_http_requests_total", **labels, status="500")
        before = metric_value(
            "pia_http_requests_total", **labels, status=metrics.DISCONNECTED_STATUS
        )

        with pytest.raises(ClientDisconnect):
            client.post("/v1/upload/sbom", json=valid_request_data)

        assert metric_value(
            "pia_http_requests_total", **labels, status=metrics.DISCONNECTED_STATUS
        ) == (before + 1)
        assert metric_value("pia_http_requests_total", **labels, status="500") == (
            before_500
        )

    def test_cancellation_is_not_counted_as_500(self, metric_value):
        """Cancellation (e.g. on shutdown) is not a server fault either.

        Driven directly: BaseHTTPMiddleware turns a CancelledError raised
        *inside* the app into "No response returned", so the only way this
        middleware sees one is from its own await being cancelled.
        """
        labels = dict(method="GET", path="<unmatched>")
        before_500 = metric_value("pia_http_requests_total", **labels, status="500")
        before = metric_value(
            "pia_http_requests_total", **labels, status=metrics.DISCONNECTED_STATUS
        )

        # Imported here: pia.main reads settings at import time, so it must
        # not be imported before the setup_env fixture has run.
        from pia.main import record_http_metrics

        async def cancel(_request):
            raise asyncio.CancelledError

        request = Request({"type": "http", "method": "GET", "headers": []})
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(record_http_metrics(request, cancel))

        assert metric_value(
            "pia_http_requests_total", **labels, status=metrics.DISCONNECTED_STATUS
        ) == (before + 1)
        assert metric_value("pia_http_requests_total", **labels, status="500") == (
            before_500
        )

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_unhandled_exception_counted_as_500(
        self, mock_upload, client, valid_request_data, metric_value
    ):
        """An exception propagating through call_next must still be counted."""
        mock_dt_response = Mock()
        mock_dt_response.ok = True
        mock_dt_response.status_code = 200
        mock_dt_response.json.return_value = {"unexpected": "shape"}
        mock_dt_response.text = '{"unexpected": "shape"}'
        mock_upload.return_value = mock_dt_response

        labels = dict(method="POST", path="/v1/upload/sbom", status="500")
        before = metric_value("pia_http_requests_total", **labels)

        with pytest.raises(KeyError):
            client.post("/v1/upload/sbom", json=valid_request_data)

        assert metric_value("pia_http_requests_total", **labels) == before + 1


@pytest.mark.usefixtures("setup_env", "authenticate_as_workload")
class TestUploadMetrics:
    """Tests for SBOM upload outcome and rejection metrics."""

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_success_outcome_and_timing(
        self, mock_upload, client, valid_request_data, metric_value
    ):
        mock_dt_response = Mock()
        mock_dt_response.ok = True
        mock_dt_response.status_code = 200
        mock_dt_response.json.return_value = {"token": "dt-token-abc"}
        mock_upload.return_value = mock_dt_response

        labels = dict(
            ef_project_id="eclipse-test",
            product_name="test-product",
            outcome="success",
        )
        before = metric_value("pia_sbom_uploads_total", **labels)
        before_dt = metric_value("pia_dependencytrack_upload_duration_seconds_count")
        before_size = metric_value("pia_sbom_size_bytes_count")

        client.post("/v1/upload/sbom", json=valid_request_data)

        assert metric_value("pia_sbom_uploads_total", **labels) == before + 1
        assert (
            metric_value("pia_dependencytrack_upload_duration_seconds_count")
            == before_dt + 1
        )
        assert metric_value("pia_sbom_size_bytes_count") == before_size + 1

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_dt_request_error_is_timed_and_counted(
        self, mock_upload, client, valid_request_data, metric_value
    ):
        """A failed upload is still timed."""
        mock_upload.side_effect = DependencyTrackError()

        labels = dict(
            ef_project_id="eclipse-test",
            product_name="test-product",
            outcome="dt_request_error",
        )
        before = metric_value("pia_sbom_uploads_total", **labels)
        before_dt = metric_value("pia_dependencytrack_upload_duration_seconds_count")

        client.post("/v1/upload/sbom", json=valid_request_data)

        assert metric_value("pia_sbom_uploads_total", **labels) == before + 1
        assert (
            metric_value("pia_dependencytrack_upload_duration_seconds_count")
            == before_dt + 1
        )

    def test_unknown_product_never_becomes_a_label(
        self, client, valid_request_data, metric_value
    ):
        """A caller-supplied product name must not reach a label (cardinality)."""
        valid_request_data["product_name"] = "unknown-product"

        before_reject = metric_value(
            "pia_upload_rejections_total", reason="no_dt_project"
        )
        before_outcome = metric_value(
            "pia_sbom_uploads_total",
            ef_project_id="eclipse-test",
            product_name="_unregistered",
            outcome="no_dt_project",
        )

        client.post("/v1/upload/sbom", json=valid_request_data)

        assert (
            metric_value("pia_upload_rejections_total", reason="no_dt_project")
            == before_reject + 1
        )
        assert (
            metric_value(
                "pia_sbom_uploads_total",
                ef_project_id="eclipse-test",
                product_name="_unregistered",
                outcome="no_dt_project",
            )
            == before_outcome + 1
        )
        assert (
            metric_value(
                "pia_sbom_uploads_total",
                ef_project_id="eclipse-test",
                product_name="unknown-product",
                outcome="no_dt_project",
            )
            == 0.0
        )


@pytest.mark.usefixtures("setup_env")
class TestRejectionReasons:
    """Every _401 branch must count its own bounded reason."""

    def _reject(self, seed_db, authorization=BEARER_TOKEN):
        from pia.main import authenticate

        with pytest.raises(HTTPException):
            asyncio.run(authenticate(authorization, seed_db))

    def test_invalid_header(self, seed_db, metric_value):
        before = metric_value("pia_upload_rejections_total", reason="invalid_header")
        self._reject(seed_db, "Basic invalid")
        assert (
            metric_value("pia_upload_rejections_total", reason="invalid_header")
            == before + 1
        )

    @patch("pia.main.jwt.decode")
    def test_invalid_token(self, mock_decode, seed_db, metric_value):
        mock_decode.side_effect = jwt.PyJWTError()
        before = metric_value("pia_upload_rejections_total", reason="invalid_token")
        self._reject(seed_db)
        assert (
            metric_value("pia_upload_rejections_total", reason="invalid_token")
            == before + 1
        )

    @patch("pia.main.jwt.decode")
    def test_issuer_not_allowed(self, mock_decode, seed_db, metric_value):
        mock_decode.return_value = {"iss": "https://wrong-issuer.com"}
        before = metric_value(
            "pia_upload_rejections_total", reason="issuer_not_allowed"
        )
        self._reject(seed_db)
        assert (
            metric_value("pia_upload_rejections_total", reason="issuer_not_allowed")
            == before + 1
        )

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_verification_failed(self, mock_decode, mock_verify, seed_db, metric_value):
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.side_effect = TokenVerificationError()
        before = metric_value(
            "pia_upload_rejections_total", reason="verification_failed"
        )
        self._reject(seed_db)
        assert (
            metric_value("pia_upload_rejections_total", reason="verification_failed")
            == before + 1
        )

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_no_workload(self, mock_decode, mock_verify, seed_db, metric_value):
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/wrong-repo",
            "repository_owner_id": "42",
        }
        before = metric_value("pia_upload_rejections_total", reason="no_workload")
        self._reject(seed_db)
        assert (
            metric_value("pia_upload_rejections_total", reason="no_workload")
            == before + 1
        )

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_claims_rejected(self, mock_decode, mock_verify, seed_db, metric_value):
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/repo",
            "repository_owner_id": "42",
            "event_name": "pull_request_target",
        }
        before = metric_value("pia_upload_rejections_total", reason="claims_rejected")
        self._reject(seed_db)
        assert (
            metric_value("pia_upload_rejections_total", reason="claims_rejected")
            == before + 1
        )

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_successful_auth_records_no_rejection(
        self, mock_decode, mock_verify, seed_db, metric_value
    ):
        """Successful auth must not touch the rejection counter."""
        from pia.main import authenticate
        from pia.metrics import RejectionReason

        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/repo",
            "repository_owner_id": "42",
            "event_name": "push",
        }
        reasons = RejectionReason.__args__
        before = sum(
            metric_value("pia_upload_rejections_total", reason=r) for r in reasons
        )

        asyncio.run(authenticate(BEARER_TOKEN, seed_db))

        after = sum(
            metric_value("pia_upload_rejections_total", reason=r) for r in reasons
        )
        assert after == before
