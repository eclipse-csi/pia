"""Tests for models module."""

import pytest
from pydantic import ValidationError

from pia.models import (
    DependencyTrackUploadPayload,
    PiaUploadPayload,
    Project,
    Projects,
)


class TestProject:
    @pytest.fixture
    def github(self, test_projects):
        return Project(**test_projects["projects"]["github-project"])

    @pytest.fixture
    def jenkins(self, test_projects):
        return Project(**test_projects["projects"]["jenkins-project"])

    def test_match_issuer(self, github):
        assert github.match_issuer("https://token.actions.githubusercontent.com")
        assert not github.match_issuer("https://githubusercontent.com")
        assert not github.match_issuer("https://token.actions.githubusercontent.com/")

    def test_match_claims(self, github, jenkins):
        assert github.match_claims({"repository": "eclipse-test/repo"})
        assert github.match_claims({"repository": "eclipse-test/repo", "a": "b"})
        assert not github.match_claims({"repo": "eclipse-test/repo"})
        assert not github.match_claims({"repository": "repo"})
        assert jenkins.match_claims({})
        assert jenkins.match_claims({"c": "d"})


class TestProjects:
    def test_load_yaml_file(self, test_projects_file, test_projects):
        projects = Projects.from_yaml_file(test_projects_file)
        assert projects == Projects(**test_projects)

    def test_find_project(self, test_projects):
        """Test finding projects by ID."""
        projects = Projects(**test_projects)

        assert projects.find_project("github-project") is not None
        assert projects.find_project("jenkins-project") is not None
        assert projects.find_project("nonexistent") is None


class TestUploadSBOMPayload:
    @pytest.fixture
    def valid_request_data(self):
        """Valid request data."""
        return {
            "project_id": "test-project",
            "product_name": "test-product",
            "product_version": "1.0.0",
            "bom": "valid_bom",
            "token": "eyJhbGciOiJSUzI1NiJ9.test.token",
        }

    def test_valid(self, valid_request_data):
        """Test creating UploadSBOMPayload from valid data."""
        payload = PiaUploadPayload(**valid_request_data)

        assert payload.project_id == "test-project"
        assert payload.product_name == "test-product"
        assert payload.product_version == "1.0.0"
        assert payload.bom == "valid_bom"
        assert payload.token == "eyJhbGciOiJSUzI1NiJ9.test.token"

    def test_missing_required_fields(self, valid_request_data):
        """Test error when a required field is missing."""
        del valid_request_data["project_id"]

        with pytest.raises(ValidationError):
            PiaUploadPayload(**valid_request_data)

        # Assert all fields are required
        assert all(
            field_info.is_required()
            for field_info in PiaUploadPayload.model_fields.values()
        )

    def test_wrong_type(self, valid_request_data):
        """Test error when field has wrong type."""
        valid_request_data["product_name"] = 123

        with pytest.raises(ValidationError):
            PiaUploadPayload(**valid_request_data)

        # Assert all fields are correctly annotated
        assert all(
            field_info.annotation is str
            for field_info in PiaUploadPayload.model_fields.values()
        )


class TestDependencyTrackPayload:
    def test_to_dict(self):
        """Test converting to dictionary with default auto_create."""
        dt_payload = DependencyTrackUploadPayload(
            project_name="test-product",
            project_version="1.0.0",
            parent_uuid="parent-uuid-123",
            bom="test-bom-data",
        )

        result = dt_payload.to_dict()

        assert result == {
            "projectName": "test-product",
            "projectVersion": "1.0.0",
            "parentUUID": "parent-uuid-123",
            "autoCreate": True,
            "bom": "test-bom-data",
        }
