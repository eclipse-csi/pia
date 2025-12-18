"""Tests for dependencytrack module."""

from unittest.mock import patch

import pytest
import requests

from pia.dependencytrack import DependencyTrackError, upload_sbom
from pia.models import DependencyTrackUploadPayload

TEST_URL = "https://dt.example.com/api/v1/bom"
TEST_API_KEY = "test-api-key"


@pytest.fixture
def dt_payload():
    """DependencyTrack payload."""
    return DependencyTrackUploadPayload(
        project_name="test-product",
        project_version="1.0.0",
        parent_uuid="parent-uuid-123",
        bom="dGVzdC1ib20tZGF0YQ==",  # base64 encoded
    )


class TestUploadSBOM:
    @patch("pia.dependencytrack.requests.post")
    def test_upload(self, mock_post, dt_payload):
        """Test request and response."""
        mock_post.return_value = "mock_response"
        result = upload_sbom(TEST_URL, TEST_API_KEY, dt_payload)

        # Assert result is request response
        assert result == "mock_response"

        # Assert request was made correctly
        mock_post.assert_called_once_with(
            "https://dt.example.com/api/v1/bom",
            json={
                "projectName": "test-product",
                "projectVersion": "1.0.0",
                "parentUUID": "parent-uuid-123",
                "autoCreate": True,
                "bom": "dGVzdC1ib20tZGF0YQ==",
            },
            headers={
                "Content-Type": "application/json",
                "X-Api-Key": "test-api-key",
            },
        )

    @patch("pia.dependencytrack.requests.post")
    def test_upload_request_exception(self, mock_post, dt_payload):
        """Test error handling."""
        mock_post.side_effect = requests.RequestException()

        with pytest.raises(
            DependencyTrackError, match="Failed to upload SBOM to DependencyTrack"
        ):
            upload_sbom(TEST_URL, TEST_API_KEY, dt_payload)
