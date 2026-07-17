"""Tests for models module."""

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from pia.models import (
    DependencyTrackProject,
    DependencyTrackUploadPayload,
    GitHubWorkload,
    JenkinsWorkload,
    PiaUploadPayload,
    find_dt_project,
    find_workload_by_claims,
    is_issuer_known,
    verify_workload_claims,
)

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"


class TestIsIssuerKnown:
    def test_github_issuer_known(self):
        assert is_issuer_known(GITHUB_ISSUER)

    def test_jenkins_issuer_known(self):
        assert is_issuer_known("https://ci.eclipse.org/eclipse-other/oidc")

    def test_jenkins_issuer_bare_host_known(self):
        assert is_issuer_known("https://ci.eclipse.org")

    def test_arbitrary_issuer_unknown(self):
        assert not is_issuer_known("https://attacker.com")

    @pytest.mark.parametrize(
        "issuer",
        [
            # Userinfo before "@": the real host is other.host, not ci.eclipse.org.
            "https://ci.eclipse.org@other.host",
            "https://ci.eclipse.org@127.0.0.1:8888",
            # Suffix on the host: ci.eclipse.org.other.host is a different host.
            "https://ci.eclipse.org.other.host",
            "https://ci.eclipse.org.other.host/eclipse-x/oidc",
            # Host is only a prefix substring, not the whole host.
            "https://ci.eclipse.org.evil.example/.well-known/openid-configuration",
        ],
    )
    def test_issuer_resolving_to_other_host_unknown(self, issuer):
        assert not is_issuer_known(issuer)

    def test_non_https_jenkins_issuer_unknown(self):
        assert not is_issuer_known("http://ci.eclipse.org/eclipse-other/oidc")

    def test_malformed_issuer_unknown(self):
        assert not is_issuer_known("ci.eclipse.org")
        assert not is_issuer_known("not a url")


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


class TestVerifyWorkloadClaims:
    @pytest.fixture
    def github_workload(self):
        return GitHubWorkload(
            ef_project_id="eclipse-test",
            repo_owner="eclipse-test",
            repo_name="repo",
            repo_owner_id="42",
        )

    @pytest.fixture
    def jenkins_workload(self):
        return JenkinsWorkload(
            ef_project_id="eclipse-other",
            issuer="https://ci.eclipse.org/eclipse-other/oidc",
        )

    @pytest.mark.parametrize("event_name", ["push", "workflow_dispatch"])
    def test_github_allowed_event(self, github_workload, event_name):
        assert (
            verify_workload_claims(github_workload, {"event_name": event_name}) is None
        )

    @pytest.mark.parametrize(
        "event_name",
        ["pull_request_target", "workflow_run", "issue_comment", "schedule", "release"],
    )
    def test_github_disallowed_event(self, github_workload, event_name):
        reason = verify_workload_claims(github_workload, {"event_name": event_name})
        assert reason is not None
        assert event_name in reason

    def test_github_missing_event(self, github_workload):
        reason = verify_workload_claims(github_workload, {})
        assert reason is not None
        assert "None" in reason

    def test_jenkins_not_checked(self, jenkins_workload):
        # No event_name check for Jenkins; any claims dict passes.
        assert verify_workload_claims(jenkins_workload, {}) is None


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


class TestDependencyTrackProjectUniqueness:
    """The two DependencyTrackProject uniqueness constraints (see models.py).

    seed_db already holds (eclipse-test, test-product, uuid-1) and
    (eclipse-other, other-product, uuid-2), with both EF projects committed.
    """

    def test_name_unique_within_ef_project(self, seed_db):
        # UNIQUE(ef_project_id, name): a second 'test-product' under eclipse-test
        # is rejected, so find_dt_project resolves a product_name unambiguously.
        seed_db.add(
            DependencyTrackProject(
                ef_project_id="eclipse-test", name="test-product", parent_uuid="uuid-x"
            )
        )
        with pytest.raises(IntegrityError):
            seed_db.commit()

    def test_same_name_allowed_across_ef_projects(self, seed_db):
        # UNIQUE(ef_project_id, name) is scoped by project: the same name under a
        # different EF project (and a different target) is allowed.
        seed_db.add(
            DependencyTrackProject(
                ef_project_id="eclipse-other", name="test-product", parent_uuid="uuid-x"
            )
        )
        seed_db.commit()  # no IntegrityError
        assert find_dt_project(seed_db, "eclipse-test", "test-product").parent_uuid == (
            "uuid-1"
        )
        assert (
            find_dt_project(seed_db, "eclipse-other", "test-product").parent_uuid
            == "uuid-x"
        )

    def test_same_name_and_parent_rejected_across_ef_projects(self, seed_db):
        # UNIQUE(name, parent_uuid) is global: even under a different EF project,
        # reusing the same physical target (name, parent_uuid) is rejected, so two
        # projects can never point at the same DependencyTrack project.
        seed_db.add(
            DependencyTrackProject(
                ef_project_id="eclipse-other", name="test-product", parent_uuid="uuid-1"
            )
        )
        with pytest.raises(IntegrityError):
            seed_db.commit()


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
