"""Pytest configuration and shared fixtures."""

import pytest
import yaml


@pytest.fixture
def test_allowlist():
    return {
        "projects": {
            "github-project": {
                "issuer": "https://token.actions.githubusercontent.com",
                "dt_parent_uuid": "uuid-1",
                "required_claims": {"repository": "eclipse-test/repo"},
            },
            "jenkins-project": {
                "issuer": "https://ci.eclipse.org/test/oidc",
                "dt_parent_uuid": "uuid-2",
            },
        }
    }


@pytest.fixture
def test_allowlist_file(tmp_path, test_allowlist):
    allowlist_path = tmp_path / "allowlist.yaml"
    with open(allowlist_path, "w") as f:
        yaml.dump(test_allowlist, f)
    return allowlist_path
