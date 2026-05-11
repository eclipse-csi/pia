"""Tests for api module."""

import asyncio
from unittest.mock import Mock, patch

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from pia.dependencytrack import DependencyTrackError
from pia.models import GitHubWorkload, Workload
from pia.oidc import TokenVerificationError

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
BEARER_TOKEN = "Bearer eyJhbGciOiJSUzI1NiJ9.test.token"


@pytest.fixture
def setup_env(monkeypatch):
    """Set required env vars for Settings()."""
    monkeypatch.setenv("PIA_DEPENDENCY_TRACK_API_KEY", "test-secret")
    # Settings requires a value, but tests override the session dependency,
    # so the URL is never actually opened.
    monkeypatch.setenv("PIA_DATABASE_URL", "sqlite:///:memory:")


@pytest.fixture
def client(setup_env, seed_db, session_factory):
    """FastAPI test client with overridden DB session."""
    from pia.main import app, get_session

    def override_get_session():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


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
        }
        result = self._call(BEARER_TOKEN, seed_db)
        assert isinstance(result, Workload)
        assert result.ef_project_id == "eclipse-test"


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
        """Successful SBOM upload."""
        mock_dt_response = Mock()
        mock_dt_response.status_code = 200
        mock_dt_response.content = b"content"
        mock_upload.return_value = mock_dt_response

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 200
        assert response.content == b"content"
        assert response.headers["content-type"] == "application/json"

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
