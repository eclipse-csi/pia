"""Tests for api module."""

from unittest.mock import Mock, patch

import jwt
import pytest
from fastapi.testclient import TestClient

from pia.dependencytrack import DependencyTrackError
from pia.oidc import TokenVerificationError


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
        "project_id": "github-project",
        "product_name": "test-product",
        "product_version": "1.0.0",
        "bom": "bom",
        "token": "eyJhbGciOiJSUzI1NiJ9.test.token",
    }


class TestUploadSBOMEndpoint:
    """Tests for /v1/upload/sbom endpoint."""

    @patch("pia.main.dependencytrack.upload_sbom")
    @patch("pia.main.oidc.verify_token")
    @patch("pia.main.jwt.decode")
    def test_upload_success(
        self, mock_decode, mock_verify, mock_upload, client, valid_request_data
    ):
        """Test successful SBOM upload."""

        # Mock token decode
        mock_decode.return_value = {
            "iss": "https://token.actions.githubusercontent.com"
        }

        # Mock token verification
        mock_verify.return_value = {
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "eclipse-test/repo",
        }

        # Mock DT upload
        mock_dt_response = Mock()
        mock_dt_response.status_code = 200
        mock_dt_response.content = b"content"
        mock_upload.return_value = mock_dt_response

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        # Assert response was correctly crafted from dt response
        assert response.status_code == 200
        assert response.content == b"content"
        assert response.headers["content-type"] == "application/json"

    def test_upload_invalid_json(self, client):
        """Test error with invalid JSON."""
        response = client.post(
            "/v1/upload/sbom",
            content=b"not-json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 422
        assert b"JSON" in response.content or b"json" in response.content

    def test_upload_missing_field(self, client, valid_request_data):
        """Test error with missing required field."""
        del valid_request_data["project_id"]

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 422
        assert b"project_id" in response.content

    def test_upload_unknown_project(self, client, valid_request_data):
        """Test error with unknown project."""
        valid_request_data["project_id"] = "unknown-project"

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 401
        assert b"Project not allowed" in response.content

    @patch("pia.main.jwt.decode")
    def test_upload_token_decode_fails(self, mock_decode, client, valid_request_data):
        """Test error when initial token decode fails."""
        mock_decode.side_effect = jwt.PyJWTError()

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 401
        assert b"Invalid token" in response.content

    @patch("pia.main.jwt.decode")
    def test_upload_issuer_not_allowed(self, mock_decode, client, valid_request_data):
        """Test error when issuer not allowed for project."""
        mock_decode.return_value = {"iss": "https://wrong-issuer.com"}

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 401
        assert b"Issuer not allowed" in response.content

    @patch("pia.main.jwt.decode")
    @patch("pia.main.oidc.verify_token")
    def test_upload_token_verification_fails(
        self, mock_verify, mock_decode, client, valid_request_data
    ):
        """Test error when token verification fails."""
        mock_decode.return_value = {
            "iss": "https://token.actions.githubusercontent.com"
        }
        mock_verify.side_effect = TokenVerificationError()

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 401
        assert b"Token verification failed" in response.content

    @patch("pia.main.jwt.decode")
    @patch("pia.main.oidc.verify_token")
    def test_upload_claims_mismatch(
        self, mock_verify, mock_decode, client, valid_request_data
    ):
        """Test error when token claims don't match required claims."""
        mock_decode.return_value = {
            "iss": "https://token.actions.githubusercontent.com"
        }

        # Claims don't match required repository
        mock_verify.return_value = {
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "wrong/repo",
        }

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 401
        assert b"Project token claim mismatch" in response.content

    @patch("pia.main.dependencytrack.upload_sbom")
    @patch("pia.main.jwt.decode")
    @patch("pia.main.oidc.verify_token")
    def test_upload_dt_error(
        self, mock_verify, mock_decode, mock_upload, client, valid_request_data
    ):
        """Test error when DependencyTrack upload fails."""
        mock_decode.return_value = {
            "iss": "https://token.actions.githubusercontent.com"
        }

        mock_verify.return_value = {
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "eclipse-test/repo",
        }

        mock_upload.side_effect = DependencyTrackError()

        response = client.post("/v1/upload/sbom", json=valid_request_data)

        assert response.status_code == 502
        assert b"Failed to upload to DependencyTrack" in response.content
