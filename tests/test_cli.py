"""Tests for the management CLI."""

from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from pia import cli as cli_module
from pia.models import (
    DependencyTrackProject,
    EclipseFoundationProject,
    GitHubWorkload,
    JenkinsWorkload,
)


def _make_response(json_data):
    r = MagicMock()
    r.json.return_value = json_data
    r.raise_for_status.return_value = None
    return r


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def patch_session(session_factory, monkeypatch):
    """Make CLI use the test session_factory instead of reading PIA_DATABASE_URL.

    PIA_DATABASE_URL still has to be set so the cli group's early-exit check
    passes; its value is irrelevant since _make_session is patched out.
    """
    monkeypatch.setenv("PIA_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setattr(cli_module, "_make_session", session_factory)


@pytest.fixture
def dt_api_key(monkeypatch):
    monkeypatch.setenv("PIA_DEPENDENCY_TRACK_API_KEY", "test-key")


def test_add_github_workload(runner, session_factory, monkeypatch):
    monkeypatch.setattr(
        cli_module.requests, "get", lambda *a, **kw: _make_response({"id": 42})
    )

    result = runner.invoke(
        cli_module.cli,
        ["add-workload", "eclipse-foo", "https://github.com/eclipse-foo/repo"],
    )
    assert result.exit_code == 0, result.output

    with session_factory() as s:
        workloads = s.query(GitHubWorkload).all()
        assert len(workloads) == 1
        w = workloads[0]
        assert w.ef_project_id == "eclipse-foo"
        assert w.repo_owner == "eclipse-foo"
        assert w.repo_name == "repo"
        assert w.repo_owner_id == "42"
        assert s.query(EclipseFoundationProject).count() == 1


def test_add_github_workload_dry_run(runner, session_factory, monkeypatch):
    monkeypatch.setattr(
        cli_module.requests, "get", lambda *a, **kw: _make_response({"id": 42})
    )

    result = runner.invoke(
        cli_module.cli,
        [
            "add-workload",
            "eclipse-foo",
            "https://github.com/eclipse-foo/repo",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output

    with session_factory() as s:
        assert s.query(GitHubWorkload).count() == 0
        assert s.query(EclipseFoundationProject).count() == 0


def test_add_jenkins_workload(runner, session_factory):
    issuer = "https://ci.eclipse.org/eclipse-bar/oidc"
    result = runner.invoke(
        cli_module.cli,
        ["add-workload", "eclipse-bar", issuer],
    )
    assert result.exit_code == 0, result.output

    with session_factory() as s:
        workloads = s.query(JenkinsWorkload).all()
        assert len(workloads) == 1
        assert workloads[0].issuer == issuer
        assert workloads[0].ef_project_id == "eclipse-bar"


def test_add_jenkins_workload_dry_run(runner, session_factory):
    issuer = "https://ci.eclipse.org/eclipse-bar/oidc"
    result = runner.invoke(
        cli_module.cli,
        ["add-workload", "eclipse-bar", issuer, "--dry-run"],
    )
    assert result.exit_code == 0, result.output

    with session_factory() as s:
        assert s.query(JenkinsWorkload).count() == 0


def test_add_workload_reuses_existing_ef_project(runner, session_factory, monkeypatch):
    with session_factory() as s:
        s.add(EclipseFoundationProject(id="eclipse-foo"))
        s.commit()

    monkeypatch.setattr(
        cli_module.requests, "get", lambda *a, **kw: _make_response({"id": 42})
    )

    result = runner.invoke(
        cli_module.cli,
        ["add-workload", "eclipse-foo", "https://github.com/eclipse-foo/repo"],
    )
    assert result.exit_code == 0, result.output

    with session_factory() as s:
        assert s.query(EclipseFoundationProject).count() == 1
        assert s.query(GitHubWorkload).count() == 1


def test_add_workload_invalid_github_url(runner):
    result = runner.invoke(
        cli_module.cli,
        ["add-workload", "eclipse-foo", "https://github.com/"],
    )
    assert result.exit_code != 0
    assert "owner/repo" in result.output


def test_missing_database_url_fails_early(runner, monkeypatch):
    """Without PIA_DATABASE_URL the cli group exits before any subcommand runs."""
    monkeypatch.delenv("PIA_DATABASE_URL", raising=False)

    def fail(*a, **kw):
        raise AssertionError("network must not be touched when DB URL is missing")

    monkeypatch.setattr(cli_module.requests, "get", fail)

    result = runner.invoke(
        cli_module.cli,
        ["add-workload", "eclipse-foo", "https://github.com/eclipse-foo/repo"],
    )
    assert result.exit_code != 0
    assert "PIA_DATABASE_URL is not set" in result.output


def test_add_dt_project(runner, session_factory, monkeypatch, dt_api_key):
    monkeypatch.setattr(
        cli_module.requests,
        "get",
        lambda *a, **kw: _make_response(
            [
                {
                    "name": "Eclipse Foo",
                    "uuid": "parent-uuid",
                    "children": [{"name": "foo-server", "uuid": "child-uuid"}],
                }
            ]
        ),
    )

    result = runner.invoke(
        cli_module.cli,
        [
            "add-dt-project",
            "eclipse-foo",
            "https://dt.example.com",
            "Eclipse Foo",
            "foo-server",
        ],
    )
    assert result.exit_code == 0, result.output

    with session_factory() as s:
        projects = s.query(DependencyTrackProject).all()
        assert len(projects) == 1
        assert projects[0].name == "foo-server"
        assert projects[0].parent_uuid == "child-uuid"
        assert projects[0].ef_project_id == "eclipse-foo"


def test_add_dt_project_dry_run(runner, session_factory, monkeypatch, dt_api_key):
    monkeypatch.setattr(
        cli_module.requests,
        "get",
        lambda *a, **kw: _make_response(
            [
                {
                    "name": "Eclipse Foo",
                    "uuid": "parent-uuid",
                    "children": [{"name": "foo-server", "uuid": "child-uuid"}],
                }
            ]
        ),
    )

    result = runner.invoke(
        cli_module.cli,
        [
            "add-dt-project",
            "eclipse-foo",
            "https://dt.example.com",
            "Eclipse Foo",
            "foo-server",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output

    with session_factory() as s:
        assert s.query(DependencyTrackProject).count() == 0
        assert s.query(EclipseFoundationProject).count() == 0


def test_add_dt_project_no_match(runner, monkeypatch, dt_api_key):
    monkeypatch.setattr(cli_module.requests, "get", lambda *a, **kw: _make_response([]))

    result = runner.invoke(
        cli_module.cli,
        [
            "add-dt-project",
            "eclipse-foo",
            "https://dt.example.com",
            "Eclipse Foo",
            "foo-server",
        ],
    )
    assert result.exit_code != 0
    assert "Expected exactly one" in result.output


def test_add_dt_project_child_not_found(runner, monkeypatch, dt_api_key):
    monkeypatch.setattr(
        cli_module.requests,
        "get",
        lambda *a, **kw: _make_response(
            [{"name": "Eclipse Foo", "uuid": "parent-uuid", "children": []}]
        ),
    )

    result = runner.invoke(
        cli_module.cli,
        [
            "add-dt-project",
            "eclipse-foo",
            "https://dt.example.com",
            "Eclipse Foo",
            "foo-server",
        ],
    )
    assert result.exit_code != 0
    assert "Expected exactly one child" in result.output
