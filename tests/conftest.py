"""Pytest configuration and shared fixtures."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pia.models import (
    Base,
    DependencyTrackProject,
    EclipseFoundationProject,
    GitHubWorkload,
    JenkinsWorkload,
)


@pytest.fixture
def engine():
    """In-memory SQLite engine, shared across threads for TestClient."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    # SQLite disables foreign-key enforcement per-connection by default; turn it
    # on so tests exercise the same referential integrity Postgres enforces in
    # production (e.g. that apply_plan deletes children before their project).
    @event.listens_for(engine, "connect")
    def _enable_sqlite_fk(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine)


@pytest.fixture
def session(session_factory):
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def seed_db(session):
    """Populate DB with two projects, two workloads, and two DT projects."""
    # Flush the parent projects before their children: the models carry no
    # relationship(), so SQLAlchemy cannot infer the insert order needed to
    # satisfy the foreign keys (now enforced under SQLite too).
    session.add_all(
        [
            EclipseFoundationProject(id="eclipse-test"),
            EclipseFoundationProject(id="eclipse-other"),
        ]
    )
    session.flush()
    session.add_all(
        [
            GitHubWorkload(
                ef_project_id="eclipse-test",
                repo_owner="eclipse-test",
                repo_name="repo",
                repo_owner_id="42",
            ),
            JenkinsWorkload(
                ef_project_id="eclipse-other",
                issuer="https://ci.eclipse.org/eclipse-other/oidc",
            ),
            DependencyTrackProject(
                ef_project_id="eclipse-test",
                name="test-product",
                parent_uuid="uuid-1",
            ),
            DependencyTrackProject(
                ef_project_id="eclipse-other",
                name="other-product",
                parent_uuid="uuid-2",
            ),
        ]
    )
    session.commit()
    return session


@pytest.fixture
def setup_env(monkeypatch):
    """Set required env vars for Settings()."""
    monkeypatch.setenv("PIA_DEPENDENCY_TRACK_API_KEY", "test-secret")
    # Settings requires a value, but tests override the session dependency,
    # so the URL is never actually opened.
    monkeypatch.setenv("PIA_DATABASE_URL", "sqlite:///:memory:")


@pytest.fixture
def client(setup_env, seed_db, session_factory):
    """FastAPI test client with overridden DB session."""
    from pia.main import app, get_session

    def override_get_session():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = override_get_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def metric_value():
    """Read a sample from the default Prometheus registry.

    Metrics are process-global and accumulate across tests (and
    `MetricWrapperBase.clear()` is a no-op for unlabeled metrics), so assert on
    the delta around an action rather than on an absolute value.
    """
    from prometheus_client import REGISTRY

    def _read(name: str, **labels: str) -> float:
        return REGISTRY.get_sample_value(name, labels or None) or 0.0

    return _read
