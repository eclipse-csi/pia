"""Tests for models module."""

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from pia.models import (
    DependencyTrackProject,
    DependencyTrackUploadPayload,
    GitHubWorkload,
    GitLabWorkload,
    JenkinsWorkload,
    PiaUploadPayload,
    find_dt_project,
    find_workload_by_claims,
    is_issuer_known,
    verify_workload_claims,
)

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
GITLAB_ISSUER = "https://gitlab.eclipse.org"


class TestIsIssuerKnown:
    def test_github_issuer_known(self, seed_db):
        assert is_issuer_known(seed_db, GITHUB_ISSUER)

    def test_gitlab_issuer_known(self, seed_db):
        assert is_issuer_known(seed_db, GITLAB_ISSUER)

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://gitlab.eclipse.org/",
            "https://gitlab.eclipse.org/eclipse/foo",
            "https://GITLAB.ECLIPSE.ORG",
            "https://gitlab.eclipse.org@evil.example",
            "https://gitlab.eclipse.org.evil.example",
            "http://gitlab.eclipse.org",
            "https://gitlab.com",
        ],
    )
    def test_gitlab_issuer_near_miss_unknown(self, seed_db, issuer):
        assert not is_issuer_known(seed_db, issuer)

    def test_jenkins_issuer_known(self, seed_db):
        assert is_issuer_known(seed_db, "https://ci.eclipse.org/eclipse-other/oidc")

    @pytest.mark.parametrize(
        "issuer",
        [
            # Prefix-only match can be bypassed with userinfo or suffix trick.
            "https://ci.eclipse.org",
            "https://ci.eclipse.org@other.host",
            "https://ci.eclipse.org@127.0.0.1:8888",
            "https://ci.eclipse.org.other.host",
            "https://ci.eclipse.org.other.host/eclipse-x/oidc",
            "https://ci.eclipse.org.evil.example/.well-known/openid-configuration",
            # Hostname parses differently in urlparse (time of check) vs.
            # requests/urllib3 (time of use).
            "https://attacker-evil-host.example:443\\@ci.eclipse.org/",
            "https://169.254.169.254:443\\@ci.eclipse.org/",
            "https://169.254.169.254\\@ci.eclipse.org/eclipse-other/oidc",
            "https://ci.eclipse.org\\.evil.example/eclipse-other/oidc",
            "https://ci.eclipse.org\t@evil.example/eclipse-other/oidc",
            "https://ci.eclipse.org\n@evil.example/eclipse-other/oidc",
            "https://ci.eclipse.org%00@evil.example/eclipse-other/oidc",
            # Unregistered issuer is rejected, even if the URL is well-formed.
            "https://ci.eclipse.org/no-such/oidc",
            # Near-match of registered issuer is rejected.
            "https://ci.eclipse.org/eclipse-other/oidc@evil.example",
            "https://ci.eclipse.org/eclipse-other/oidc.evil.example",
            "https://ci.eclipse.org/eclipse-other/oidc?next=@evil.example",
            "https://ci.eclipse.org/eclipse-other/oidc#@evil.example",
            "https://ci.eclipse.org:443/eclipse-other/oidc",
            "https://CI.ECLIPSE.ORG/eclipse-other/oidc",
            # Wrong host, scheme, or not a URL at all.
            "https://attacker.com",
            "http://ci.eclipse.org/eclipse-other/oidc",
            "file:///etc/passwd",
            "ci.eclipse.org",
            "not a url",
            "",
        ],
    )
    def test_issuer_unknown(self, seed_db, issuer):
        assert not is_issuer_known(seed_db, issuer)

    @pytest.mark.parametrize(
        "issuer",
        [
            # The unverified `iss` claim may be any JSON type.
            1234,
            True,
            [],
            ["https://ci.eclipse.org/eclipse-other/oidc"],
            {"a": 1},
        ],
    )
    def test_non_string_issuer_unknown(self, seed_db, issuer):
        assert not is_issuer_known(seed_db, issuer)

    @pytest.mark.parametrize(
        "issuer",
        [
            # Text the database driver cannot encode; must not reach the query.
            "https://ci.eclipse.org/\x00",
            "https://ci.eclipse.org/eclipse-other\x00/oidc",
            "https://ci.eclipse.org/\ud800",
            "https://ci.eclipse.org/eclipse-other\ud800/oidc",
            # Control characters
            "https://ci.eclipse.org/eclipse-other/oidc\n",
            "https://ci.eclipse.org/eclipse-other\x1b/oidc",
        ],
    )
    def test_malformed_issuer_unknown(self, seed_db, issuer):
        assert not is_issuer_known(seed_db, issuer)


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

    @pytest.mark.parametrize(
        "claims",
        [
            # Text the database driver cannot encode
            {"repository": "eclipse-test/repo\x00", "repository_owner_id": "42"},
            {"repository": "eclipse-test/repo\ud800", "repository_owner_id": "42"},
            {"repository": "eclipse-test/repo", "repository_owner_id": "42\x00"},
            {"repository": "eclipse-test/repo", "repository_owner_id": "42\ud800"},
            # Control characters
            {"repository": "eclipse-test/repo\n", "repository_owner_id": "42"},
            {"repository": "eclipse-test/repo", "repository_owner_id": "42\x1b"},
            # Wrong type or missing
            {"repository": ["eclipse-test/repo"], "repository_owner_id": "42"},
            {"repository": "eclipse-test/repo", "repository_owner_id": 42},
            {"repository": "eclipse-test/repo"},
        ],
    )
    def test_github_malformed_claims(self, seed_db, claims):
        workload = find_workload_by_claims(seed_db, {"iss": GITHUB_ISSUER, **claims})
        assert workload is None

    def test_gitlab_match(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITLAB_ISSUER,
                "project_path": "eclipse/test/repo",
                "project_id": "16770",
            },
        )
        assert isinstance(workload, GitLabWorkload)
        assert workload.ef_project_id == "eclipse-test"

    def test_gitlab_wrong_path(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITLAB_ISSUER,
                "project_path": "eclipse/test/other-repo",
                "project_id": "16770",
            },
        )
        assert workload is None

    def test_gitlab_path_case_mismatch(self, seed_db):
        # The sync CLI stores the canonical path, and the token carries the
        # canonical path, so matching is deliberately exact.
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITLAB_ISSUER,
                "project_path": "Eclipse/Test/Repo",
                "project_id": "16770",
            },
        )
        assert workload is None

    def test_gitlab_resurrected_project(self, seed_db):
        # Same path, different project id: the registered project was deleted
        # (possibly with its whole namespace) and re-created. Rejected until
        # the curated file is re-synced.
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITLAB_ISSUER,
                "project_path": "eclipse/test/repo",
                "project_id": "99999",
            },
        )
        assert workload is None

    def test_gitlab_fork_merge_request_pipeline(self, seed_db):
        # A fork's merge request pipeline run in the parent project: the
        # `job_project_*` and `ci_config_ref_uri` claims name the registered
        # parent, but `project_path`/`project_id` name the fork. Matching on
        # the latter is the security property; do NOT "fix" this by matching
        # `job_project_*`.
        workload = find_workload_by_claims(
            seed_db,
            {
                "iss": GITLAB_ISSUER,
                "project_path": "attacker/repo",
                "project_id": "31337",
                "namespace_path": "attacker",
                "job_project_path": "eclipse/test/repo",
                "job_project_id": "16770",
                "source_project_path": "attacker/repo",
                "source_project_id": "31337",
                "ci_config_ref_uri": (
                    "gitlab.eclipse.org/eclipse/test/repo//.gitlab-ci.yml"
                    "@refs/heads/main"
                ),
                "pipeline_source": "merge_request_event",
            },
        )
        assert workload is None

    @pytest.mark.parametrize(
        "claims",
        [
            {},
            {"project_path": "eclipse/test/repo"},
            {"project_id": "16770"},
            {"project_path": ["eclipse/test/repo"], "project_id": "16770"},
            {"project_path": "eclipse/test/repo", "project_id": 16770},
            {"project_path": None, "project_id": "16770"},
            # Text the database driver cannot encode
            {"project_path": "eclipse/test/repo\x00", "project_id": "16770"},
            {"project_path": "eclipse/test/repo", "project_id": "16770\ud800"},
            # Control characters
            {"project_path": "eclipse/test/repo\n", "project_id": "16770"},
            {"project_path": "eclipse/test/repo", "project_id": "16770\x1b"},
        ],
    )
    def test_gitlab_missing_or_malformed_claims(self, seed_db, claims):
        workload = find_workload_by_claims(seed_db, {"iss": GITLAB_ISSUER, **claims})
        assert workload is None

    def test_jenkins_match(self, seed_db):
        workload = find_workload_by_claims(
            seed_db,
            {"iss": "https://ci.eclipse.org/eclipse-other/oidc"},
        )
        assert isinstance(workload, JenkinsWorkload)
        assert workload.ef_project_id == "eclipse-other"

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://ci.eclipse.org/eclipse-other\x00/oidc",
            "https://ci.eclipse.org/eclipse-other\ud800/oidc",
            "https://ci.eclipse.org/eclipse-other/oidc\n",
        ],
    )
    def test_jenkins_malformed_issuer(self, seed_db, issuer):
        workload = find_workload_by_claims(seed_db, {"iss": issuer})
        assert workload is None

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
    def gitlab_workload(self):
        return GitLabWorkload(
            ef_project_id="eclipse-test",
            project_path="eclipse/test/repo",
            project_id="16770",
        )

    @pytest.fixture
    def jenkins_workload(self):
        return JenkinsWorkload(
            ef_project_id="eclipse-other",
            issuer="https://ci.eclipse.org/eclipse-other/oidc",
        )

    @pytest.mark.parametrize(
        "event_name", ["push", "workflow_dispatch", "release", "schedule"]
    )
    def test_github_allowed_event(self, github_workload, event_name):
        assert (
            verify_workload_claims(github_workload, {"event_name": event_name}) is None
        )

    @pytest.mark.parametrize(
        "event_name",
        ["pull_request_target", "workflow_run", "issue_comment", "issues", "fork"],
    )
    def test_github_disallowed_event(self, github_workload, event_name):
        reason = verify_workload_claims(github_workload, {"event_name": event_name})
        assert reason is not None
        assert event_name in reason

    def test_github_missing_event(self, github_workload):
        reason = verify_workload_claims(github_workload, {})
        assert reason is not None
        assert "None" in reason

    @pytest.mark.parametrize("value", [["push"], {"push": 1}, 1])
    def test_non_string_event_name(self, github_workload, value):
        # Unhashable values must not raise on the frozenset lookup
        assert verify_workload_claims(github_workload, {"event_name": value})

    @pytest.mark.parametrize("pipeline_source", ["push", "web", "schedule", "api"])
    def test_gitlab_allowed_pipeline_source(self, gitlab_workload, pipeline_source):
        assert (
            verify_workload_claims(
                gitlab_workload, {"pipeline_source": pipeline_source}
            )
            is None
        )

    @pytest.mark.parametrize(
        "pipeline_source",
        [
            "merge_request_event",
            "external_pull_request_event",
            "trigger",
            "pipeline",
            "parent_pipeline",
            "chat",
            "webide",
        ],
    )
    def test_gitlab_disallowed_pipeline_source(self, gitlab_workload, pipeline_source):
        reason = verify_workload_claims(
            gitlab_workload, {"pipeline_source": pipeline_source}
        )
        assert reason is not None
        assert pipeline_source in reason
        assert "push" in reason

    @pytest.mark.parametrize("value", [["push"], {"push": 1}, 1])
    def test_gitlab_non_string_pipeline_source(self, gitlab_workload, value):
        # Unhashable values must not raise on the frozenset lookup
        assert verify_workload_claims(gitlab_workload, {"pipeline_source": value})

    def test_gitlab_missing_pipeline_source(self, gitlab_workload):
        reason = verify_workload_claims(gitlab_workload, {})
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

    @pytest.mark.parametrize(
        "field,value",
        [
            ("product_name", "test-product\x00"),
            ("product_name", "test-product\ud800"),
            ("product_name", "test\nproduct"),
            ("product_name", ""),
            ("product_version", "1.0\x00"),
            ("product_version", "1.0\ud800"),
            ("product_version", "1.0\x1b[2J"),
            ("product_version", ""),
            ("product_name", b"test-product"),
            ("is_latest", 1),
            ("is_latest", "true"),
        ],
    )
    def test_malformed_value(self, valid_request_data, field, value):
        valid_request_data[field] = value
        with pytest.raises(ValidationError):
            PiaUploadPayload(**valid_request_data)

    def test_printable_non_ascii_allowed(self, valid_request_data):
        valid_request_data["product_name"] = "prodüct Ω"
        assert PiaUploadPayload(**valid_request_data).product_name == "prodüct Ω"


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
