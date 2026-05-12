"""Pytest configuration and shared fixtures."""

import pytest
from sqlalchemy import create_engine
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
    session.add_all(
        [
            EclipseFoundationProject(id="eclipse-test"),
            EclipseFoundationProject(id="eclipse-other"),
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
