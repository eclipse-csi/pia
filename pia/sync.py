"""Declarative sync of project authorizations from a curated file into the DB.

Reconciles the whole authorization state against a human-curated file (the single
source of truth): it creates new entries, updates changed ones, and deletes entries
that are no longer in the file.

The file is a list of Eclipse Foundation projects, each with a flat list of workload
URLs (GitHub repo or Jenkins instance URL — the type is inferred from the host) and a
list of DependencyTrack (parent, project) mappings. A Jenkins workload is listed as
its instance URL; PIA appends ``/oidc`` to derive the OIDC issuer:

    projects:
      - id: technology.foo
        workloads:
          - https://github.com/eclipse-foo/repo
          - https://ci.eclipse.org/foo
        dependency_track:
          - parent: "Eclipse Foo"
            project: foo-server
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import click
import requests
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    GITHUB_BASE_URL,
    JENKINS_ISSUER_BASE_URL,
    JENKINS_OIDC_SUFFIX,
    DependencyTrackProject,
    EclipseFoundationProject,
    GitHubWorkload,
    JenkinsWorkload,
)

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Curated-file model
# --------------------------------------------------------------------------- #


class DtProjectSpec(BaseModel):
    """A DependencyTrack (root project, child project) mapping."""

    model_config = ConfigDict(extra="forbid")

    parent: str
    project: str


class ProjectSpec(BaseModel):
    """One Eclipse Foundation project and everything authorized for it."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workloads: list[str] = Field(default_factory=list)
    dependency_track: list[DtProjectSpec] = Field(default_factory=list)


class ProjectsFile(BaseModel):
    """Top-level curated file."""

    model_config = ConfigDict(extra="forbid")

    projects: list[ProjectSpec] = Field(default_factory=list)


def load_projects_file(path: str) -> ProjectsFile:
    """Parse and structurally validate the curated file at ``path``."""
    with open(path) as fh:
        raw = yaml.safe_load(fh)
    try:
        return ProjectsFile.model_validate(raw)
    except ValidationError as e:
        raise click.ClickException(f"Invalid projects file {path!r}:\n{e}") from e


def classify_workload_url(url: str) -> tuple[str, str, str]:
    """Classify a workload URL by host.

    Returns ``("github", repo_owner, repo_name)`` for a github.com repo URL or
    ``("jenkins", issuer, "")`` for a ci.eclipse.org Jenkins instance URL. In the
    Jenkins case the URL is the *workload* URL (``https://ci.eclipse.org/<name>``)
    and the returned issuer is that URL with ``/oidc`` appended — the file lists
    workloads, PIA derives the issuer. Raises ``click.ClickException`` for anything
    else. No network access.
    """
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.hostname}"

    if base_url == GITHUB_BASE_URL:
        parts = [seg for seg in parsed.path.split("/") if seg]
        if len(parts) != 2:
            raise click.ClickException(
                f"GitHub URL must be '{GITHUB_BASE_URL}/<owner>/<repo>': {url}"
            )
        return ("github", parts[0], parts[1])

    if base_url == JENKINS_ISSUER_BASE_URL:
        parts = [seg for seg in parsed.path.split("/") if seg]
        if len(parts) != 1:
            raise click.ClickException(
                f"Jenkins URL must be {JENKINS_ISSUER_BASE_URL}/<name>: {url}"
            )
        issuer = f"{JENKINS_ISSUER_BASE_URL}/{parts[0]}{JENKINS_OIDC_SUFFIX}"
        return ("jenkins", issuer, "")

    raise click.ClickException(
        f"URL must be a {GITHUB_BASE_URL} repo URL or a "
        f"{JENKINS_ISSUER_BASE_URL} instance URL: {url}"
    )


def validate_projects_file(pf: ProjectsFile) -> None:
    """Semantic validation beyond structural parsing (no network access).

    Enforces: unique project ids; every workload URL is a valid GitHub/Jenkins
    URL and globally unique; DependencyTrack project names are unique within a
    project and DependencyTrack (parent, project) mappings are unique across
    the whole file.
    """
    # Raise on duplicate project IDs
    ids = [p.id for p in pf.projects]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise click.ClickException(f"Duplicate project id(s): {', '.join(dupes)}")

    seen_workloads: set[tuple[str, str, str]] = set()
    seen_dt_pairs: set[tuple[str, str]] = set()
    for project in pf.projects:
        # Raise on invalid or duplicate **resolved** workloads URLs
        for url in project.workloads:
            workload = classify_workload_url(url)
            if workload in seen_workloads:
                raise click.ClickException(f"Duplicate resolved workload URL(s): {url}")
            seen_workloads.add(workload)

        # Raise on global duplicate DependencyTrack project names
        seen_dt_names: set[str] = set()
        for dt in project.dependency_track:
            if dt.project in seen_dt_names:
                raise click.ClickException(
                    f"Duplicate DependencyTrack project name(s) in {project.id!r}: "
                    f"{dt.project}"
                )
            seen_dt_names.add(dt.project)

            # Raise on global duplicate DependencyTrack parent/project pairs
            pair = (dt.parent, dt.project)
            if pair in seen_dt_pairs:
                raise click.ClickException(
                    "Duplicate DependencyTrack (parent, project) mapping(s): "
                    f"{dt.parent}/{dt.project}"
                )
            seen_dt_pairs.add(pair)


# --------------------------------------------------------------------------- #
# Resolution (external lookups)
# --------------------------------------------------------------------------- #

JSON_TYPE = "application/json"


def fetch_github_owner_id(owner: str, token: str | None = None) -> str:
    """Resolve a GitHub owner login to its numeric id.

    An optional token is sent as a Bearer credential to lift the anonymous rate
    limit (only public read is needed for ``GET /users/{owner}``).
    """
    url = f"https://api.github.com/users/{owner}"
    logger.info(f"Fetching GitHub owner id from {url}")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    owner_id = str(response.json()["id"])
    logger.info(f"GitHub owner {owner!r} has id {owner_id}")
    return owner_id


def _dt_search_root_projects(
    dt_url: str, name: str, api_key: str
) -> list[dict[str, Any]]:
    """Return all root DependencyTrack projects with the given name."""
    url = f"{dt_url.rstrip('/')}/api/v1/project"
    logger.info(f"Querying DependencyTrack root projects at {url} for name={name!r}")
    response = requests.get(
        url,
        params={"name": name, "onlyRoot": "true"},
        headers={"X-Api-Key": api_key, "Accept": JSON_TYPE},
    )
    response.raise_for_status()
    return response.json()


def _dt_create_project(
    dt_url: str, name: str, api_key: str, parent_uuid: str | None = None
) -> dict[str, Any]:
    """Create a DependencyTrack project (root if ``parent_uuid`` is None)."""
    where = f"under parent {parent_uuid}" if parent_uuid else "(root)"
    logger.info(f"Creating DependencyTrack project {name!r} {where}")
    body: dict[str, Any] = {"name": name}
    if parent_uuid:
        body["parent"] = {"uuid": parent_uuid}
    response = requests.put(
        f"{dt_url.rstrip('/')}/api/v1/project",
        json=body,
        headers={
            "X-Api-Key": api_key,
            "Accept": JSON_TYPE,
            "Content-Type": JSON_TYPE,
        },
    )
    response.raise_for_status()
    return response.json()


_missing_dt_hint = " — run `pia create-dt-projects` to provision it first"


def _resolve_one_or_create(
    matches: list[dict[str, Any]],
    msg: str,
    create: bool,
    factory: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Pick the single match, create one, or raise on a missing/ambiguous match."""
    if len(matches) == 1:
        return matches[0]
    if create and not matches:
        return factory()
    hint = _missing_dt_hint if not matches and not create else ""
    raise click.ClickException(
        f"Expected exactly one DependencyTrack {msg}, found {len(matches)}{hint}"
    )


def resolve_dt_child_uuid(
    dt_url: str,
    parent_name: str,
    project_name: str,
    api_key: str,
    root_cache: dict[str, dict[str, Any]] | None = None,
    create: bool = False,
) -> str:
    """Resolve the UUID of child ``project_name`` under root ``parent_name``.

    ``root_cache`` memoises root-project lookups by name so a sync that reuses the
    same DT root across many mappings issues one request per root; pass ``None``
    for a one-off lookup. When ``create`` is set, a missing root or child project
    is created rather than raising; an *ambiguous* match is always an error.
    """
    if root_cache is None:
        root_cache = {}

    parent = root_cache.get(parent_name)
    if parent is None:
        parents = _dt_search_root_projects(dt_url, parent_name, api_key)
        parent = _resolve_one_or_create(
            parents,
            f"root project named {parent_name!r}",
            create,
            lambda: _dt_create_project(dt_url, parent_name, api_key),
        )
        parent.setdefault("children", [])
        root_cache[parent_name] = parent

    children = [c for c in parent["children"] if c.get("name") == project_name]
    child = _resolve_one_or_create(
        children,
        f"child project {project_name!r} under root project {parent_name!r}",
        create,
        lambda: _dt_create_project(dt_url, project_name, api_key, parent["uuid"]),
    )
    if child not in parent["children"]:
        # Update cache with newly created child
        parent["children"].append(child)
    return child["uuid"]


def ensure_dt_projects(
    pf: ProjectsFile, dt_url: str, dt_api_key: str
) -> list[tuple[str, str]]:
    """Create any missing DependencyTrack projects for the file's DT mappings.

    For every ``(parent, project)`` mapping in the curated file, ensure the root
    and child project exist on DependencyTrack, creating whichever are missing.
    This is the provisioning step behind ``pia create-dt-projects``: it touches
    only DependencyTrack (no PIA database, no GitHub) and is idempotent — an
    existing project is resolved, not recreated. Requires a DT API key with
    PORTFOLIO_MANAGEMENT permission. Returns the ``(parent, project)`` pairs it
    ensured, for reporting.
    """
    root_cache: dict[str, dict[str, Any]] = {}
    ensured: list[tuple[str, str]] = []
    for project in pf.projects:
        for dt in project.dependency_track:
            resolve_dt_child_uuid(
                dt_url, dt.parent, dt.project, dt_api_key, root_cache, create=True
            )
            ensured.append((dt.parent, dt.project))
    return ensured


# --------------------------------------------------------------------------- #
# DB state
# --------------------------------------------------------------------------- #


@dataclass
class DB:
    """A snapshot of the DB entities, keyed by ``diff_key`` for set-diffing.

    Used for both the desired state (built from the curated file by
    build_desired) and the current state (loaded from the DB by _load_current).
    Each entity exposes its own ``diff_key`` (see models.py) — the tuple of all
    its business columns — so build_desired and _load_current key through the same
    source of truth and the two sides of the diff can never drift.
    """

    ef: dict[tuple[str, ...], EclipseFoundationProject] = field(default_factory=dict)
    github: dict[tuple[str, ...], GitHubWorkload] = field(default_factory=dict)
    jenkins: dict[tuple[str, ...], JenkinsWorkload] = field(default_factory=dict)
    dt: dict[tuple[str, ...], DependencyTrackProject] = field(default_factory=dict)


def build_desired(
    pf: ProjectsFile,
    dt_url: str,
    dt_api_key: str,
    github_token: str | None = None,
) -> DB:
    """Resolve the curated file into a fully-populated desired state.

    Performs the external lookups (GitHub owner ids, DependencyTrack child UUIDs).
    ``dt_url`` and ``dt_api_key`` are required (the CLI validates their presence).
    DependencyTrack projects are only *resolved* here, never created: a missing one
    raises, directing the operator to run ``pia create-dt-projects`` first.
    """
    desired = DB()
    owner_id_cache: dict[str, str] = {}
    dt_root_cache: dict[str, dict[str, Any]] = {}

    for project in pf.projects:
        ef = EclipseFoundationProject(id=project.id)
        desired.ef[ef.diff_key] = ef

        for url in project.workloads:
            kind, a, b = classify_workload_url(url)
            if kind == "github":
                owner, repo = a, b
                if owner not in owner_id_cache:
                    owner_id_cache[owner] = fetch_github_owner_id(owner, github_token)
                gh = GitHubWorkload(
                    ef_project_id=project.id,
                    repo_owner=owner,
                    repo_name=repo,
                    repo_owner_id=owner_id_cache[owner],
                )
                desired.github[gh.diff_key] = gh
            else:
                issuer = a
                jk = JenkinsWorkload(ef_project_id=project.id, issuer=issuer)
                desired.jenkins[jk.diff_key] = jk

        for dt in project.dependency_track:
            child_uuid = resolve_dt_child_uuid(
                dt_url,
                dt.parent,
                dt.project,
                dt_api_key,
                dt_root_cache,
            )
            dtp = DependencyTrackProject(
                ef_project_id=project.id,
                name=dt.project,
                parent_uuid=child_uuid,
            )
            desired.dt[dtp.diff_key] = dtp

    return desired


# --------------------------------------------------------------------------- #
# Diff / plan
# --------------------------------------------------------------------------- #


@dataclass
class Plan:
    """A reconciliation plan: what to create and delete.

    Modifications are expressed as delete+create for simplicity of this tool
    and its output. They should be rare anyway.

    Eclipse Foundation project creates/deletes are separate from the
    creates/deletes lists of child DependencyTrack projects and workloads, to
    assure foreign-key ordering: child rows reference the parent via
    ef_project_id, so they must be deleted before their parents, and vice-versa
    parents must be created before their children.
    """

    ef_create: list[EclipseFoundationProject] = field(default_factory=list)
    ef_delete: list[EclipseFoundationProject] = field(default_factory=list)
    creates: list[Any] = field(default_factory=list)
    deletes: list[Any] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.ef_create or self.ef_delete or self.creates or self.deletes)


def _load_current(session: Session) -> DB:
    return DB(
        ef={
            p.diff_key: p
            for p in session.execute(select(EclipseFoundationProject)).scalars()
        },
        github={
            w.diff_key: w for w in session.execute(select(GitHubWorkload)).scalars()
        },
        jenkins={
            w.diff_key: w for w in session.execute(select(JenkinsWorkload)).scalars()
        },
        dt={
            d.diff_key: d
            for d in session.execute(select(DependencyTrackProject)).scalars()
        },
    )


def compute_plan(session: Session, desired: DB) -> Plan:
    """Diff the desired state against the current DB state. No writes.

    The diff is a set difference over each entity's diff_key: a key only in
    desired is a create, a key only in current is a delete, and a row whose
    business columns changed shows up as both (its diff_key differs on each
    side), i.e. a delete of the old row plus a create of the new one.
    """
    current = _load_current(session)
    plan = Plan()

    # Eclipse Foundation projects go in their own buckets so apply_plan can
    # honour foreign-key ordering (see Plan). Creates carry the transient desired
    # row, deletes the attached current one, so apply_plan neither reconstructs
    # nor re-fetches them.
    plan.ef_create = [
        desired.ef[k] for k in sorted(desired.ef.keys() - current.ef.keys())
    ]
    plan.ef_delete = [
        current.ef[k] for k in sorted(current.ef.keys() - desired.ef.keys())
    ]

    for cur, des in (
        (current.github, desired.github),
        (current.jenkins, desired.jenkins),
        (current.dt, desired.dt),
    ):
        plan.creates += [des[k] for k in sorted(des.keys() - cur.keys())]
        plan.deletes += [cur[k] for k in sorted(cur.keys() - des.keys())]

    return plan


def format_plan(plan: Plan) -> str:
    """Render a plan as a human-readable, reviewable block.

    Shows a create block then a delete block, each rendered from the rows'
    ``__repr__``. Within a block, Eclipse Foundation projects lead on create and
    trail on delete, mirroring apply_plan's foreign-key-safe ordering.
    """
    if plan.is_empty():
        return "Plan: no changes — database already matches the file."
    creates = [*plan.ef_create, *plan.creates]
    deletes = [*plan.deletes, *plan.ef_delete]
    out = [f"Plan: {len(creates)} to create, {len(deletes)} to delete"]
    if creates:
        out += ["", "Create:", "-" * 7, *(f"+ {obj!r}" for obj in creates)]
    if deletes:
        out += ["", "Delete:", "-" * 7, *(f"- {obj!r}" for obj in deletes)]
    return "\n".join(out)


def apply_plan(session: Session, plan: Plan) -> None:
    """Apply a plan within the given session's transaction (no commit).

    Order matters against the foreign keys: delete child rows, then empty
    parents; create new parents before their children. Deleting (and flushing)
    before creating also frees unique keys, so a modification expressed as
    delete+create of the same business key does not collide with its own old
    row.
    """
    # 1. Delete Workload / DependencyTrack rows before deleting referenced
    # EF projects
    for obj in plan.deletes:
        session.delete(obj)
    session.flush()
    # 2. Delete now unreferenced EF projects
    for obj in plan.ef_delete:
        session.delete(obj)
    session.flush()
    # 3. Create EF projects before any referencing them
    for obj in plan.ef_create:
        session.add(obj)
    session.flush()
    # 4. Create Workload / DependencyTrack rows with references to just created
    # EF projects
    for obj in plan.creates:
        session.add(obj)
    session.flush()
