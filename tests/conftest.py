"""Pytest configuration and shared fixtures."""

import pytest
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
