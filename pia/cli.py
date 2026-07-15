"""Management CLI for PIA.

Subcommands
-----------
- sync: Reconcile all project authorizations from a curated file into the
  database (create/update/delete).
- create-dt-projects: Create the DependencyTrack projects referenced by a curated
  file (provisioning only; no database access).

Usage Example
-------------
    PIA_DATABASE_URL=postgresql://user:secret@localhost:5432/pia \
    PIA_DEPENDENCY_TRACK_API_KEY=<API key with VIEW_PORTFOLIO permission> \
    PIA_GITHUB_TOKEN=<optional token with public read permission for rate limit> \
        uv run pia sync projects.yaml --dt-url https://sbom.eclipse.org --dry-run

    PIA_DEPENDENCY_TRACK_API_KEY=<API key with PORTFOLIO_MANAGEMENT permission> \
        uv run pia create-dt-projects projects.yaml --dt-url https://sbom.eclipse.org

"""

import logging
import os

import click
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .sync import (
    apply_plan,
    build_desired,
    compute_plan,
    ensure_dt_projects,
    format_plan,
    load_projects_file,
    validate_projects_file,
)


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
def cli(verbose: bool) -> None:
    """PIA management CLI."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _make_session() -> Session:
    engine = create_engine(os.environ["PIA_DATABASE_URL"])
    return sessionmaker(bind=engine)()


@cli.command("sync")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--dt-url",
    default=None,
    help="DependencyTrack base URL (required). This is the base, not the "
    "/api/v1/bom upload URL.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show the plan without writing to the PIA database.",
)
@click.option(
    "--check",
    is_flag=True,
    help="Validate the file only; performs no database or network access.",
)
@click.option(
    "--allow-db-updates-and-deletions",
    is_flag=True,
    help="Apply the plan even when it contains updates or deletions to existing "
    "rows in the PIA database. Explicit intent is required to prevent accidental "
    "deauthorization of projects.",
)
def sync(
    file: str,
    dt_url: str | None,
    dry_run: bool,
    check: bool,
    allow_db_updates_and_deletions: bool,
) -> None:
    """Reconcile all authorizations from a curated FILE into the database.

    Computes the difference between the file (the source of truth) and the
    current database state, prints the plan, and — unless --dry-run — applies
    it, creating, updating and deleting rows to match the file.

    The DependencyTrack projects referenced by the file must already exist; a
    missing one is an error. Run `pia create-dt-projects` first to provision them.

    Requires PIA_DATABASE_URL, --dt-url, and PIA_DEPENDENCY_TRACK_API_KEY (with
    VIEW_PORTFOLIO permission). PIA_GITHUB_TOKEN is optional and only lifts the
    anonymous GitHub rate limit.
    """
    pf = load_projects_file(file)
    validate_projects_file(pf)
    if check:
        click.echo(f"OK: {file} is valid ({len(pf.projects)} project(s)).")
        return

    if not os.environ.get("PIA_DATABASE_URL"):
        raise click.ClickException("PIA_DATABASE_URL is not set")

    dt_api_key = os.environ.get("PIA_DEPENDENCY_TRACK_API_KEY")
    if not dt_url or not dt_api_key:
        raise click.ClickException(
            "--dt-url and PIA_DEPENDENCY_TRACK_API_KEY are required"
        )

    desired = build_desired(
        pf,
        dt_url=dt_url,
        dt_api_key=dt_api_key,
        github_token=os.environ.get("PIA_GITHUB_TOKEN"),
    )

    with _make_session() as session:
        plan = compute_plan(session, desired)
        click.echo(format_plan(plan))

        if dry_run or plan.is_empty():
            session.rollback()
            return

        if (plan.ef_delete or plan.deletes) and not allow_db_updates_and_deletions:
            session.rollback()
            raise click.ClickException(
                "Plan contains updates and/or deletions; re-run with "
                "--allow-db-updates-and-deletions to apply (or --dry-run to "
                "preview)."
            )

        apply_plan(session, plan)
        session.commit()
        click.echo("Applied.")


@cli.command("create-dt-projects")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--dt-url",
    default=None,
    help="DependencyTrack base URL (required). This is the base, not the "
    "/api/v1/bom upload URL.",
)
def create_dt_projects(file: str, dt_url: str | None) -> None:
    """Create the DependencyTrack projects referenced by a curated FILE.

    Ensures every (parent, project) DependencyTrack mapping in the file exists,
    creating any missing root/child projects. Provisioning only — it does not touch
    the PIA database, so run it before `pia sync` whenever a file introduces new
    DependencyTrack targets. Idempotent: existing projects are left as-is.

    Requires --dt-url and PIA_DEPENDENCY_TRACK_API_KEY (with PORTFOLIO_MANAGEMENT
    permission to create projects).
    """
    pf = load_projects_file(file)
    validate_projects_file(pf)

    dt_api_key = os.environ.get("PIA_DEPENDENCY_TRACK_API_KEY")
    if not dt_url or not dt_api_key:
        raise click.ClickException(
            "--dt-url and PIA_DEPENDENCY_TRACK_API_KEY are required"
        )

    ensured = ensure_dt_projects(pf, dt_url, dt_api_key)
    click.echo(
        f"Ensured {len(ensured)} DependencyTrack (parent, project) mapping(s) on "
        f"{dt_url}."
    )


if __name__ == "__main__":
    cli()
