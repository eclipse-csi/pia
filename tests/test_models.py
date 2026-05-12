"""Tests for models module."""

import pytest
from pydantic import ValidationError

from pia.models import (
    DependencyTrackUploadPayload,
    GitHubWorkload,
    JenkinsWorkload,
    PiaUploadPayload,
    find_dt_project,
    find_workload_by_claims,
    is_issuer_known,
)

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"


class TestIsIssuerKnown:
    def test_github_issuer_known(self):
        assert is_issuer_known(GITHUB_ISSUER)

    def test_jenkins_issuer_known(self):
        assert is_issuer_known("https://ci.eclipse.org/eclipse-other/oidc")

    def test_arbitrary_issuer_unknown(self):
        assert not is_issuer_known("https://attacker.com")


class TestFindWorkloadByClaims:
    def test_github_match(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITHUB_ISSUER,
                "repository": "eclipse-test/repo",
                "repository_owner_id": "42",
            },
        )
        assert isinstance(workload, GitHubWorkload)
        assert workload.ef_project_id == "eclipse-test"

    def test_github_wrong_repo(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITHUB_ISSUER,
                "repository": "eclipse-test/wrong-repo",
                "repository_owner_id": "42",
            },
        )
        assert workload is None

    def test_github_wrong_owner_id(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITHUB_ISSUER,
                "repository": "eclipse-test/repo",
                "repository_owner_id": "999",
            },
        )
        assert workload is None

    def test_github_malformed_repository_claim(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {"iss": GITHUB_ISSUER, "repository": "no-slash"},
        )
        assert workload is None

    def test_github_missing_repository_claim(self, seed_db):
        workload = find_workload_by_claims(seed_db, {"iss": GITHUB_ISSUER})
        assert workload is None

    def test_jenkins_match(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {"iss": "https://ci.eclipse.org/eclipse-other/oidc"},
        )
        assert isinstance(workload, JenkinsWorkload)
        assert workload.ef_project_id == "eclipse-other"

    def test_jenkins_no_match(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {"iss": "https://ci.eclipse.org/no-such-project/oidc"},
        )
        assert workload is None


class TestFindDtProject:
    def test_match(self, seed_db):
        dt_project = find_dt_project(seed_db, "eclipse-test", "test-product")
        assert dt_project is not None
        assert dt_project.parent_uuid == "uuid-1"

    def test_wrong_project(self, seed_db):
        # 'test-product' exists for eclipse-test, but not for eclipse-other
        dt_project = find_dt_project(seed_db, "eclipse-other", "test-product")
        assert dt_project is None

    def test_wrong_name(self, seed_db):
        dt_project = find_dt_project(seed_db, "eclipse-test", "no-such-product")
        assert dt_project is None


class TestUploadSBOMPayload:
    @pytest.fixture
    def valid_request_data(self):
        return {
            "product_name": "test-product",
            "product_version": "1.0.0",
            "bom": "valid_bom",
        }

    def test_valid(self, valid_request_data):
        payload = PiaUploadPayload(**valid_request_data)
        assert payload.product_name == "test-product"
        assert payload.product_version == "1.0.0"
        assert payload.bom == "valid_bom"
        assert payload.is_latest is True

        payload = PiaUploadPayload(**valid_request_data, is_latest=False)
        assert payload.is_latest is False

    @pytest.mark.parametrize("field", ["product_name", "product_version", "bom"])
    def test_missing_required_field(self, valid_request_data, field):
        del valid_request_data[field]
        with pytest.raises(ValidationError):
            PiaUploadPayload(**valid_request_data)

    @pytest.mark.parametrize(
        "field,value",
        [
            ("product_name", 123),
            ("product_version", 123),
            ("bom", 123),
            ("is_latest", "not-a-bool"),
        ],
    )
    def test_wrong_type(self, valid_request_data, field, value):
        valid_request_data[field] = value
        with pytest.raises(ValidationError):
            PiaUploadPayload(**valid_request_data)


class TestDependencyTrackPayload:
    def test_to_dict(self):
        dt_payload = DependencyTrackUploadPayload(
            project_name="test-product",
            project_version="1.0.0",
            parent_uuid="parent-uuid-123",
            is_latest=True,
            bom="test-bom-data",
        )

        assert dt_payload.to_dict() == {
            "projectName": "test-product",
            "projectVersion": "1.0.0",
            "parentUUID": "parent-uuid-123",
            "autoCreate": True,
            "isLatest": True,
            "bom": "test-bom-data",
        }
