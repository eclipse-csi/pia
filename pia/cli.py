"""Management CLI for registering workloads and DependencyTrack projects.

Subcommands
-----------
- add-workload: Register a CI/CD workload that is allowed to upload SBOMs for an
  Eclipse Foundation project.

- add-dt-project: Register a DependencyTrack project as the upload target for a
  given Eclipse Foundation project.

Usage Examples
--------------
Register GitHub Actions:

    PIA_DATABASE_URL=postgresql://user:secret@localhost:5432/pia \
        uv run pia add-workload eclipse-foo \
                https://github.com/eclipse-foo/repo

Register Jenkins Instance:

    PIA_DATABASE_URL=postgresql://user:secret@localhost:5432/pia \
        uv run pia add-workload eclipse-bar \
                https://ci.eclipse.org/eclipse-bar/oidc

Register DependencyTrack Project:

    PIA_DATABASE_URL=postgresql://user:secret@localhost:5432/pia \
    PIA_DEPENDENCY_TRACK_API_KEY=<API key with VIEW_PORTFOLIO permission> \
        uv run pia add-dt-project eclipse-baz \
                https://sbom.eclipse.org "Eclipse Baz" baz-server

"""

import logging
import os
from typing import Any
from urllib.parse import urlparse

import click
import requests
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import (
    JENKINS_ISSUER_PREFIX,
    DependencyTrackProject,
    EclipseFoundationProject,
    GitHubWorkload,
    JenkinsWorkload,
    Workload,
)

logger = logging.getLogger(__name__)


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def cli(verbose: bool) -> None:
    """PIA management CLI."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Fail early if the DB URL is missing — both subcommands need it, and we
    # don't want to discover this after the GitHub / DependencyTrack lookups.
    if not os.environ.get("PIA_DATABASE_URL"):
        raise click.ClickException("PIA_DATABASE_URL is not set")


def _make_session() -> Session:
    engine = create_engine(os.environ["PIA_DATABASE_URL"])
    return sessionmaker(bind=engine)()


def _get_dt_api_key() -> str:
    key = os.environ.get("PIA_DEPENDENCY_TRACK_API_KEY")
    if not key:
        raise click.ClickException("PIA_DEPENDENCY_TRACK_API_KEY is not set")
    return key


def _create_ef_project_if_needed(session: Session, ef_project_id: str) -> None:
    if session.get(EclipseFoundationProject, ef_project_id) is None:
        logger.info(f"Creating EclipseFoundationProject {ef_project_id!r}")
        session.add(EclipseFoundationProject(id=ef_project_id))
    else:
        logger.info(f"Using existing EclipseFoundationProject {ef_project_id!r}")


def _fetch_github_owner_id(owner: str) -> str:
    url = f"https://api.github.com/users/{owner}"
    logger.info(f"Fetching GitHub owner id from {url}")
    response = requests.get(url, headers={"Accept": "application/vnd.github+json"})
    response.raise_for_status()
    owner_id = str(response.json()["id"])
    logger.info(f"GitHub owner {owner!r} has id {owner_id}")
    return owner_id


def _dt_find_root_project_by_name(
    dt_url: str, name: str, api_key: str
) -> dict[str, Any]:
    """Look up a root DependencyTrack project by name, asserting exactly one match."""
    url = f"{dt_url.rstrip('/')}/api/v1/project"
    logger.info(f"Querying DependencyTrack root projects at {url} for name={name!r}")
    response = requests.get(
        url,
        params={"name": name, "onlyRoot": "true"},
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
    )
    response.raise_for_status()
    projects = response.json()
    if len(projects) != 1:
        raise click.ClickException(
            f"Expected exactly one root DependencyTrack project named {name!r}, "
            f"found {len(projects)}"
        )
    return projects[0]


@cli.command("add-workload")
@click.argument("ef_project_id")
@click.argument("url")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Look up data and prepare the row, but do not commit.",
)
def add_workload(ef_project_id: str, url: str, dry_run: bool) -> None:
    """Register a GitHub or Jenkins workload for an Eclipse Foundation project.

    URL type is determined by its value: github.com URLs create a GitHubWorkload,
    URLs starting with the Jenkins issuer prefix create a JenkinsWorkload with the
    URL as issuer. Any other URL is rejected.
    """
    parsed = urlparse(url)
    if parsed.netloc == "github.com":
        path_parts = parsed.path.strip("/").split("/")
        if len(path_parts) != 2 or not all(path_parts):
            raise click.ClickException(f"GitHub URL must include owner/repo: {url}")
        owner, repo = path_parts[0], path_parts[1]
        owner_id = _fetch_github_owner_id(owner)
        workload: Workload = GitHubWorkload(
            ef_project_id=ef_project_id,
            repo_owner=owner,
            repo_name=repo,
            repo_owner_id=owner_id,
        )
        logger.info(
            f"Prepared GitHubWorkload(ef_project_id={ef_project_id!r}, "
            f"repo_owner={owner!r}, repo_name={repo!r}, repo_owner_id={owner_id})"
        )
    elif url.startswith(JENKINS_ISSUER_PREFIX):
        workload = JenkinsWorkload(ef_project_id=ef_project_id, issuer=url)
        logger.info(
            f"Prepared JenkinsWorkload(ef_project_id={ef_project_id!r}, issuer={url!r})"
        )
    else:
        raise click.ClickException(
            f"URL must be a GitHub repo URL or start with {JENKINS_ISSUER_PREFIX!r}: "
            f"{url}"
        )

    with _make_session() as session:
        _create_ef_project_if_needed(session, ef_project_id)
        session.add(workload)
        if dry_run:
            logger.info("Dry-run: rolling back transaction")
            session.rollback()
        else:
            session.commit()
            logger.info("Committed workload")


@cli.command("add-dt-project")
@click.argument("ef_project_id")
@click.argument("dt_url")
@click.argument("parent_name")
@click.argument("project_name")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Look up data and prepare the row, but do not commit.",
)
def add_dt_project(
    ef_project_id: str,
    dt_url: str,
    parent_name: str,
    project_name: str,
    dry_run: bool,
) -> None:
    """Register a DependencyTrack project for an Eclipse Foundation project.

    Fetches the root project matching PARENT_NAME (asserting exactly one), then
    finds PROJECT_NAME among its children (asserting exactly one), and stores
    that child's UUID.
    """
    api_key = _get_dt_api_key()

    parent = _dt_find_root_project_by_name(dt_url, parent_name, api_key)
    logger.info(f"Resolved parent {parent_name!r} -> uuid={parent['uuid']}")

    children = [c for c in parent.get("children", []) if c.get("name") == project_name]
    if len(children) != 1:
        raise click.ClickException(
            f"Expected exactly one child named {project_name!r} under {parent_name!r}, "
            f"found {len(children)}"
        )
    child_uuid = children[0]["uuid"]
    logger.info(f"Resolved child {project_name!r} -> uuid={child_uuid}")

    dt_project = DependencyTrackProject(
        ef_project_id=ef_project_id,
        name=project_name,
        parent_uuid=child_uuid,
    )
    logger.info(
        f"Prepared DependencyTrackProject(ef_project_id={ef_project_id!r}, "
        f"name={project_name!r}, parent_uuid={child_uuid})"
    )

    with _make_session() as session:
        _create_ef_project_if_needed(session, ef_project_id)
        session.add(dt_project)
        if dry_run:
            logger.info("Dry-run: rolling back transaction")
            session.rollback()
        else:
            session.commit()
            logger.info("Committed DependencyTrack project")


if __name__ == "__main__":
    cli()
