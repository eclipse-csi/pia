"""Pytest configuration and shared fixtures."""

import pytest
import yaml


@pytest.fixture
def test_projects():
    return [
        {
            "project_id": "github-project",
            "issuer": "https://token.actions.githubusercontent.com",
            "dt_parent_uuid": "uuid-1",
            "required_claims": {"repository": "eclipse-test/repo"},
        },
        {
            "project_id": "jenkins-project",
            "issuer": "https://ci.eclipse.org/test/oidc",
            "dt_parent_uuid": "uuid-2",
        },
    ]


@pytest.fixture
def test_projects_file(tmp_path, test_projects):
    projects_path = tmp_path / "projects.yaml"
    with open(projects_path, "w") as f:
        yaml.dump(test_projects, f)
    return projects_path
