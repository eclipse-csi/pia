"""Tests for api module."""

import asyncio
from unittest.mock import Mock, patch

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from pia.dependencytrack import DependencyTrackError
from pia.models import Project
from pia.oidc import TokenVerificationError

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
BEARER_TOKEN = "Bearer eyJhbGciOiJSUzI1NiJ9.test.token"


@pytest.fixture
def setup_env(test_projects_file):
    """Provide temporary projects file and assign env variables."""
    import os

    os.environ["PIA_DEPENDENCY_TRACK_API_KEY"] = "test-secret"
    os.environ["PIA_PROJECTS_PATH"] = str(test_projects_file)
    yield
    del os.environ["PIA_DEPENDENCY_TRACK_API_KEY"]
    del os.environ["PIA_PROJECTS_PATH"]


@pytest.fixture
def client(setup_env):
    """Create FastAPI test client with projects loaded."""
    from pia.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def valid_request_data():
    """Valid request data for SBOM upload."""
    return {
        "product_name": "test-product",
        "product_version": "1.0.0",
        "bom": "bom",
    }


@pytest.fixture
def auth_header():
    """Valid Authorization header with Bearer token."""
    return {"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.test.token"}


@pytest.fixture
def authenticate_as_project():
    """Skips authentication and returns a mock authenticated project."""
    from pia.main import app, authenticate

    mock_project = Project(
        project_id="github-project",
        issuer="https://token.actions.githubusercontent.com",
        dt_parent_uuid="uuid-1",
        required_claims={"repository": "eclipse-test/repo"},
    )

    app.dependency_overrides[authenticate] = lambda: mock_project
    yield
    app.dependency_overrides.clear()


@pytest.mark.usefixtures("setup_env")
class TestAuthenticate:
    """Tests for the authenticate dependency, called as a regular function."""

    def _call(self, authorization, projects):
        from pia.main import authenticate

        return asyncio.run(authenticate(authorization, projects))

    def test_invalid_authorization_header(self, projects):
        """Error when Authorization header doesn't start with 'Bearer '."""
        with pytest.raises(HTTPException) as exc:
            self._call("Basic invalid", projects)
        assert exc.value.status_code == 401
        assert "Invalid Authorization header format" in exc.value.detail

    @patch("pia.main.jwt.decode")
    def test_token_decode_fails(self, mock_decode, projects):
        """Error when initial token decode fails."""
        mock_decode.side_effect = jwt.PyJWTError()
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, projects)
        assert exc.value.status_code == 401
        assert "Invalid token" in exc.value.detail

    @patch("pia.main.jwt.decode")
    def test_issuer_not_allowed(self, mock_decode, projects):
        """Error when issuer is not registered with any project."""
        mock_decode.return_value = {"iss": "https://wrong-issuer.com"}
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, projects)
        assert exc.value.status_code == 401
        assert "Issuer not allowed" in exc.value.detail

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_token_verification_fails(self, mock_decode, mock_verify, projects):
        """Error when token signature verification fails."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.side_effect = TokenVerificationError()
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, projects)
        assert exc.value.status_code == 401
        assert "Token verification failed" in exc.value.detail

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_no_matching_project(self, mock_decode, mock_verify, projects):
        """Error when no project matches the verified token claims."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "wrong/repo",
        }
        with pytest.raises(HTTPException) as exc:
            self._call(BEARER_TOKEN, projects)
        assert exc.value.status_code == 401
        assert "No matching project found for token claims" in exc.value.detail

    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_success(self, mock_decode, mock_verify, projects):
        """Successful authentication returns the matched project."""
        mock_decode.return_value = {"iss": GITHUB_ISSUER}
        mock_verify.return_value = {
            "iss": GITHUB_ISSUER,
            "repository": "eclipse-test/repo",
        }
        result = self._call(BEARER_TOKEN, projects)
        assert result.project_id == "github-project"


class TestUploadSBOMEndpoint:
    """Tests for /v1/upload/sbom endpoint."""

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_upload_success(
        self,
        mock_upload,
        client,
        valid_request_data,
        authenticate_as_project,
    ):
        """Test successful SBOM upload."""
        mock_dt_response = Mock()
        mock_dt_response.status_code = 200
        mock_dt_response.content = b"content"
        mock_upload.return_value = mock_dt_response

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 200
        assert response.content == b"content"
        assert response.headers["content-type"] == "application/json"

    def test_upload_invalid_json(self, client, authenticate_as_project):
        """Test error with invalid JSON."""
        response = client.post(
            "/v1/upload/sbom",
            content=b"not-json",
        )

        assert response.status_code == 422
        assert b"JSON" in response.content or b"json" in response.content

    def test_upload_missing_field(
        self, client, valid_request_data, authenticate_as_project
    ):
        """Test error with missing required field."""
        del valid_request_data["product_name"]

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 422
        assert b"product_name" in response.content

    @patch("pia.main.dependencytrack.upload_sbom")
    def test_upload_dt_error(
        self,
        mock_upload,
        client,
        valid_request_data,
        authenticate_as_project,
    ):
        """Test error when DependencyTrack upload fails."""
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
