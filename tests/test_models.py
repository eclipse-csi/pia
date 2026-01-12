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
        return Project(**test_projects[0])

    @pytest.fixture
    def jenkins(self, test_projects):
        return Project(**test_projects[1])

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
        assert projects == Projects(test_projects)

    def test_has_issuer(self, test_projects):
        """Test checking if issuer exists in any project."""
        projects = Projects(test_projects)

        assert projects.has_issuer("https://token.actions.githubusercontent.com")
        assert projects.has_issuer("https://ci.eclipse.org/test/oidc")
        assert not projects.has_issuer("https://unknown-issuer.com")

    def test_find_project_by_claims_github(self, test_projects):
        """Test finding GitHub project by matching claims."""
        projects = Projects(test_projects)

        # Matching claims
        project = projects.find_project_by_claims(
            {
                "iss": "https://token.actions.githubusercontent.com",
                "repository": "eclipse-test/repo",
            }
        )
        assert project is not None
        assert project.project_id == "github-project"

        # Wrong repository claim
        project = projects.find_project_by_claims(
            {
                "iss": "https://token.actions.githubusercontent.com",
                "repository": "wrong/repo",
            }
        )
        assert project is None

        # Missing repository claim
        project = projects.find_project_by_claims(
            {
                "iss": "https://token.actions.githubusercontent.com",
            }
        )
        assert project is None

    def test_find_project_by_claims_jenkins(self, test_projects):
        """Test finding Jenkins project by matching claims (issuer only)."""
        projects = Projects(test_projects)

        # Jenkins project has no required claims, only issuer match needed
        project = projects.find_project_by_claims(
            {
                "iss": "https://ci.eclipse.org/test/oidc",
            }
        )
        assert project is not None
        assert project.project_id == "jenkins-project"

    def test_find_project_by_claims_unknown_issuer(self, test_projects):
        """Test no match when issuer is unknown."""
        projects = Projects(test_projects)

        project = projects.find_project_by_claims(
            {
                "iss": "https://unknown-issuer.com",
                "repository": "eclipse-test/repo",
            }
        )
        assert project is None


class TestUploadSBOMPayload:
    @pytest.fixture
    def valid_request_data(self):
        """Valid request data."""
        return {
            "product_name": "test-product",
            "product_version": "1.0.0",
            "bom": "valid_bom",
        }

    def test_valid(self, valid_request_data):
        """Test creating UploadSBOMPayload from valid data."""
        payload = PiaUploadPayload(**valid_request_data)

        assert payload.product_name == "test-product"
        assert payload.product_version == "1.0.0"
        assert payload.bom == "valid_bom"

    def test_missing_required_fields(self, valid_request_data):
        """Test error when a required field is missing."""
        del valid_request_data["product_name"]

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
