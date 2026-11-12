"""ORM models for projects/workloads/products and Pydantic request models."""

import logging
from typing import Annotated, Any, TypeGuard

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, HttpUrl
from sqlalchemy import ForeignKey, MetaData, Select, String, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger(__name__)


GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
"""OIDC issuer for GitHub Actions tokens. Constant across all GitHub workloads."""

GITHUB_BASE_URL = "https://github.com"
"""Scheme and host of the GitHub repo URLs accepted when registering workloads."""

GITLAB_ISSUER = "https://gitlab.eclipse.org"
"""OIDC issuer for Eclipse GitLab CI tokens. Constant across all GitLab workloads.

Also the scheme and host of the GitLab project URLs accepted when registering
workloads: a self-managed GitLab instance issues tokens at its own origin."""

JENKINS_ISSUER_BASE_URL = "https://ci.eclipse.org"
"""Scheme and host every Jenkins issuer URL must have."""

JENKINS_OIDC_SUFFIX = "/oidc"
"""Path suffix appended to a Jenkins workload URL to form its OIDC issuer.

Each Eclipse Jenkins project serves its issuer at
``https://ci.eclipse.org/<name>/oidc`` (see docs/DESIGN.md §7.2). Curated
project files list the workload URL (``https://ci.eclipse.org/<name>``); PIA
appends this suffix."""

GITHUB_ALLOWED_EVENT_NAMES = frozenset(
    {"push", "workflow_dispatch", "release", "schedule"}
)
"""Allowed values for the GitHub OIDC token's `event_name` claim.

Restricts the OIDC mint to events that only a maintainer can cause: `push`,
`workflow_dispatch` and `release` all require write access to the repo, and
`schedule` takes no external input and runs the default branch's workflow
file. Excludes triggers like `pull_request_target`, `workflow_run`, and
`issue_comment` that can be indirectly driven by non-maintainers. Relax on
demand."""

GITLAB_ALLOWED_PIPELINE_SOURCES = frozenset({"push", "web", "schedule", "api"})
"""Allowed values for the GitLab OIDC token's `pipeline_source` claim.

Restricts the OIDC mint to pipelines that only a committer (Developer role or
above) can cause: `push` and `web` (the "Run pipeline" button) require write
access to the project, and `schedule` runs as the committer who owns the
schedule. `api` (the Pipelines API) adds no publisher: it needs a user or
access token with `api` scope and the Developer role, which can already push
commits and so cause a `push` pipeline.

Excludes `trigger`: a pipeline trigger token can start pipelines but not
push, and it is meant to be handed to other projects and systems, so
allowing it would let non-committers publish. Also excludes
`external_pull_request_event`, which a GitHub-mirror pull request from anyone
can drive, and `merge_request_event`, which publishes unmerged code. Relax on
demand."""


def is_printable_str(value: Any) -> TypeGuard[str]:
    """True for a str that is entirely printable (`str.isprintable`).

    This excludes control characters, NUL and lone surrogates, but also other
    non-printable characters such as format characters (e.g. zero-width joiner,
    soft hyphen) and separators other than ASCII space (e.g. no-break space).

    Untrusted text (token claims, payload fields) must pass this before it is
    compared or bound into a query: the db driver cannot encode NUL or lone
    surrogates and would raise.
    """
    return isinstance(value, str) and value.isprintable()


NAMING_CONVENTION = {
    "ix": "%(table_name)s_%(column_0_N_name)s_idx",
    "uq": "%(table_name)s_%(column_0_N_name)s_key",
    "ck": "%(table_name)s_%(constraint_name)s_check",
    "fk": "%(table_name)s_%(column_0_N_name)s_fkey",
    "pk": "%(table_name)s_pkey",
}
"""DB constraint naming convention modeled after PostgreSQL default names, and
used by `alembic revision --autogenerate`.

See https://alembic.sqlalchemy.org/en/latest/naming.html"""


class Base(DeclarativeBase):
    """Declarative base class for all ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class EclipseFoundationProject(Base):
    """Eclipse Foundation project. Groups workloads and DependencyTrack projects.

    https://www.eclipse.org/projects/handbook/#resources-identifiers
    """

    __tablename__ = "eclipse_foundation_projects"

    # `Mapped[str]` is the type annotation SQLAlchemy reads to infer the column
    # type and nullability; `mapped_column(...)` provides runtime column options.
    #
    # The PK is the Eclipse project identifier itself. It is the authorization
    # scope: every workload and DependencyTrack row is anchored to one project
    # via its `ef_project_id` foreign key. Uniqueness is implicit through the
    # single column.
    id: Mapped[str] = mapped_column(String, primary_key=True)

    @property
    def diff_key(self) -> tuple[str, ...]:
        return (self.id,)

    def __repr__(self) -> str:
        # extra space is intentional to align with other models
        return f"Eclipse Project  ({self.id})"


class Workload(Base):
    """CI/CD entity authorized to upload SBOMs.

    Polymorphic base — see GitHubWorkload, GitLabWorkload and JenkinsWorkload.
    Uses joined-table inheritance: each subclass gets its own table sharing the
    `id` PK with this base table. SQLAlchemy uses the `type` discriminator
    column to instantiate the right subclass when loading rows.
    """

    __tablename__ = "workloads"

    # Autoincrementing integer PK.
    id: Mapped[int] = mapped_column(primary_key=True)
    # `onupdate="CASCADE"` propagates ef_project_id changes from the parent
    # eclipse_foundation_projects row to all referencing rows.
    ef_project_id: Mapped[str] = mapped_column(
        ForeignKey(
            "eclipse_foundation_projects.id",
            onupdate="CASCADE",
        ),
    )
    # Discriminator column. Values come from subclass's
    # `__mapper_args__["polymorphic_identity"]`.
    type: Mapped[str] = mapped_column(String)

    __mapper_args__ = {
        # Identity to write into `type` if a Workload is instantiated directly
        # (we don't expect that, but SQLAlchemy requires a value).
        "polymorphic_identity": "workload",
        # Tell the mapper to dispatch on `type` when loading rows.
        "polymorphic_on": "type",
    }

    # Uniqueness constraint: A workload identity is globally unique and maps to
    # exactly one EF project. Mapping a workload to multiple EF projects is
    # possible, but would require a model and auth flow re-design. See
    # subclasses for constraint definitions.


class GitHubWorkload(Workload):
    """GitHub Actions workload. Issuer is always GITHUB_ISSUER."""

    __tablename__ = "github_workloads"

    id: Mapped[int] = mapped_column(ForeignKey(Workload.id), primary_key=True)
    repo_name: Mapped[str] = mapped_column(String)
    repo_owner: Mapped[str] = mapped_column(String)
    repo_owner_id: Mapped[str] = mapped_column(String)

    # See parent class for details about the uniqueness constraint.
    __table_args__ = (UniqueConstraint("repo_name", "repo_owner", "repo_owner_id"),)

    __mapper_args__ = {
        "polymorphic_identity": "github",
    }

    @property
    def diff_key(self) -> tuple[str, ...]:
        return (self.ef_project_id, self.repo_owner, self.repo_name, self.repo_owner_id)

    def __repr__(self) -> str:
        # extra space is intentional to align with other models
        return (
            f"GitHub Workload  (project: {self.ef_project_id}, "
            f"repo: {self.repo_owner}/{self.repo_name}, owner id: {self.repo_owner_id})"
        )


class GitLabWorkload(Workload):
    """Eclipse GitLab CI workload. Issuer is always GITLAB_ISSUER.

    `project_id` is the resurrection guard: it is the never-reused numeric id
    of the exact GitLab project, so a project (or its whole namespace) deleted
    and re-created at the same path no longer matches until it is re-synced.
    No separate namespace id is needed for that: deleting a group deletes its
    projects, and on Eclipse GitLab all projects live under the Eclipse
    Foundation-managed root group.
    """

    __tablename__ = "gitlab_workloads"

    id: Mapped[int] = mapped_column(ForeignKey(Workload.id), primary_key=True)
    project_path: Mapped[str] = mapped_column(String)
    project_id: Mapped[str] = mapped_column(String)

    # See parent class for details about the uniqueness constraint.
    __table_args__ = (UniqueConstraint("project_path", "project_id"),)

    __mapper_args__ = {
        "polymorphic_identity": "gitlab",
    }

    @property
    def diff_key(self) -> tuple[str, ...]:
        return (self.ef_project_id, self.project_path, self.project_id)

    def __repr__(self) -> str:
        # extra space is intentional to align with other models
        return (
            f"GitLab Workload  (project: {self.ef_project_id}, "
            f"path: {self.project_path}, project id: {self.project_id})"
        )


class JenkinsWorkload(Workload):
    """Jenkins workload. Each instance has a distinct issuer URL."""

    __tablename__ = "jenkins_workloads"

    id: Mapped[int] = mapped_column(ForeignKey(Workload.id), primary_key=True)

    # See parent class for details about the uniqueness constraint.
    issuer: Mapped[str] = mapped_column(String, unique=True)

    __mapper_args__ = {
        "polymorphic_identity": "jenkins",
    }

    @property
    def diff_key(self) -> tuple[str, ...]:
        return (self.ef_project_id, self.issuer)

    def __repr__(self) -> str:
        return (
            f"Jenkins Workload (project: {self.ef_project_id}, issuer: {self.issuer})"
        )


class DependencyTrackProject(Base):
    """DependencyTrack target for SBOM uploads.

    ``name`` is the DependencyTrack name shared by two projects: the
    version-less "product aggregation project", whose UUID is ``parent_uuid``,
    and the per-version "product project" DependencyTrack auto-creates on each
    upload. It is matched against ``product_name`` from the PIA upload::

        <DependencyTrack project>   root, one per Eclipse Foundation project
        └── <name>                  product aggregation — parent_uuid points here
            └── <name> <version>    auto-created per upload, one per version
    """

    __tablename__ = "dependency_track_projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    ef_project_id: Mapped[str] = mapped_column(
        ForeignKey(
            "eclipse_foundation_projects.id",
            onupdate="CASCADE",
        ),
    )
    name: Mapped[str] = mapped_column(String)
    parent_uuid: Mapped[str] = mapped_column(String)

    # UNIQUE("name", "parent_uuid"): A DependencyTrack target belongs to exactly
    # one EF project, so an upload authorized for one can never reach
    # another's. Caveat: This holds as long as `name` and `parent_uuid` in a
    # row refer to the same DependencyTrack project. However, an incoherent row
    # would escape the constraint, since uploads are routed by `parent_uuid`
    # alone:
    # ("eclipse.foo", "cli", "UUID-A") and ("eclipse.bar", "cli-other", "UUID-A")
    # satisfy the constraint, while sending both projects into "UUID-A".
    # `pia sync` guarantees coherency.
    #
    # UNIQUE("ef_project_id", "name"): A `product_name` must resolve to at most
    # one `name` within the authenticated workload's EF project in
    # `find_dt_project`. This constraint is a defensive policy, to avoid a 500
    # on upload due to an unhandled `MultipleResultsFound` from
    # `scalar_one_or_none`, if the assumption from above does not hold true.
    #
    # Neither constraint makes `name` globally unique, so two EF projects can
    # each claim a product named "cli" here. `validate_projects_file` rejects
    # that outright — the curated file is the only writer, and DependencyTrack
    # would refuse the second one at provisioning anyway.
    #
    # TODO: Consider replacing both constraints with single-column constraints
    # on "name" and "parent_uuid" — or on "name" alone, once "parent_uuid" is
    # dropped with eclipse-csi/pia#79.
    __table_args__ = (
        UniqueConstraint("name", "parent_uuid"),
        UniqueConstraint("ef_project_id", "name"),
    )

    @property
    def diff_key(self) -> tuple[str, ...]:
        return (self.ef_project_id, self.name, self.parent_uuid)

    def __repr__(self) -> str:
        # extra space is intentional to align with other models
        return (
            f"DependencyTrack  (project: {self.ef_project_id}, "
            f"name: {self.name}, parent id: {self.parent_uuid})"
        )


def is_issuer_known(session: Session, issuer: object) -> bool:
    """Check if issuer is known to PIA.

    GitHub: issuer must equal GITHUB_ISSUER
    GitLab: issuer must equal GITLAB_ISSUER
    Jenkins: issuer must equal the issuer of a registered JenkinsWorkload in DB
    """
    # The issuer comes from an unverified token and may be any JSON type, or
    # text the db driver cannot encode
    if not is_printable_str(issuer):
        return False

    if issuer in (GITHUB_ISSUER, GITLAB_ISSUER):
        return True

    # Preliminary host check to skip more costly db query below for obvious junk
    if not issuer.startswith(JENKINS_ISSUER_BASE_URL + "/"):
        return False

    # More costly, but also more robust than a URL pattern match
    stmt = select(JenkinsWorkload.id).where(JenkinsWorkload.issuer == issuer)
    return session.execute(stmt).first() is not None


def find_workload_by_claims(
    session: Session, token_claims: dict[str, Any]
) -> Workload | None:
    """Find Workload matching verified token claims.

    GitHub: match by repo_owner, repo_name, repo_owner_id.
    GitLab: match by project_path, project_id.
    Jenkins: match by exact issuer.
    Returns None if no match.
    """
    issuer = token_claims["iss"]
    logger.debug(f"Searching for workload matching issuer {issuer!a} and token claims")

    stmt: Select[Any]
    if issuer == GITHUB_ISSUER:
        repository = token_claims.get("repository")
        repo_owner_id = token_claims.get("repository_owner_id")
        if (
            not is_printable_str(repository)
            or "/" not in repository
            or not is_printable_str(repo_owner_id)
        ):
            logger.info(
                f"GitHub token missing or malformed 'repository' or "
                f"'repository_owner_id' claim: "
                f"{repository!a}, {repo_owner_id!a}"
            )
            return None
        repo_owner, repo_name = repository.split("/", 1)
        stmt = select(GitHubWorkload).where(
            GitHubWorkload.repo_owner == repo_owner,
            GitHubWorkload.repo_name == repo_name,
            GitHubWorkload.repo_owner_id == repo_owner_id,
        )
    elif issuer == GITLAB_ISSUER:
        # Match `project_path`/`project_id`, NOT `job_project_*`: in a merge
        # request pipeline these name the MR's *source* project, i.e. the fork
        # when a fork's MR pipeline runs in the parent project, while
        # `job_project_*` and `ci_config_ref_uri` name the parent. Matching
        # the source project is what keeps a fork from publishing as the
        # parent (see threat-model.md, P-WORKLOAD-BIND).
        project_path = token_claims.get("project_path")
        project_id = token_claims.get("project_id")
        if not is_printable_str(project_path) or not is_printable_str(project_id):
            logger.info(
                f"GitLab token missing or malformed 'project_path' or 'project_id' "
                f"claim: {project_path!a}, {project_id!a}"
            )
            return None
        stmt = select(GitLabWorkload).where(
            GitLabWorkload.project_path == project_path,
            GitLabWorkload.project_id == project_id,
        )
    else:
        if not is_printable_str(issuer):
            logger.info(f"Token has malformed Jenkins 'iss' claim: {issuer!a}")
            return None
        stmt = select(JenkinsWorkload).where(JenkinsWorkload.issuer == issuer)
    return session.execute(stmt).scalar_one_or_none()


def verify_workload_claims(workload: Workload, claims: dict[str, Any]) -> str | None:
    """Workload-type-specific claim verification beyond the workload-match step.

    Returns a human-readable reason on rejection, or None on success.

    NOTE: The reason is included in the response, so it must not include
    sensitive information.

    """
    if isinstance(workload, GitHubWorkload):
        event_name = claims.get("event_name")
        # isinstance first: an unhashable claim (list, dict) would raise
        if not isinstance(event_name, str) or (
            event_name not in GITHUB_ALLOWED_EVENT_NAMES
        ):
            return (
                f"GitHub event_name {event_name!r} not in allowlist "
                f"{sorted(GITHUB_ALLOWED_EVENT_NAMES)}"
            )
    elif isinstance(workload, GitLabWorkload):
        pipeline_source = claims.get("pipeline_source")
        # isinstance first: an unhashable claim (list, dict) would raise
        if not isinstance(pipeline_source, str) or (
            pipeline_source not in GITLAB_ALLOWED_PIPELINE_SOURCES
        ):
            return (
                f"GitLab pipeline_source {pipeline_source!r} not in allowlist "
                f"{sorted(GITLAB_ALLOWED_PIPELINE_SOURCES)}"
            )
    return None


def find_dt_project(
    session: Session, ef_project_id: str, name: str
) -> DependencyTrackProject | None:
    """Find DependencyTrackProject by name within an Eclipse Foundation project."""
    stmt = select(DependencyTrackProject).where(
        DependencyTrackProject.ef_project_id == ef_project_id,
        DependencyTrackProject.name == name,
    )
    return session.execute(stmt).scalar_one_or_none()


def _printable(value: str) -> str:
    # NOTE: Must not echo the value: it is untrusted and may be unencodable
    if not is_printable_str(value):
        raise ValueError("String should contain only printable characters")
    return value


PrintableStr = Annotated[str, Field(min_length=1), AfterValidator(_printable)]
"""Non-empty, entirely printable string (see `is_printable_str`)."""


class PiaUploadPayload(BaseModel):
    """Payload for PIA SBOM upload.

    Strict: no type coercion, and `product_name` and `product_version` must be
    printable (see `PrintableStr`). `bom` is left to DependencyTrack to validate.
    """

    product_name: PrintableStr
    """
    Name of product for which the SBOM is produced. This field is required by
    DependencyTrack to aggregate SBOMs by product within a project.
    """

    product_version: PrintableStr
    """
    Version of product for which the SBOM was produced
    """

    bom: str
    """
    Base64-encoded CycloneDX JSON SBOM
    """

    is_latest: bool = True
    """
    Whether this SBOM should be marked as the latest version in DependencyTrack
    """

    model_config = ConfigDict(strict=True, use_attribute_docstrings=True)


class PiaUploadResponse(BaseModel):
    """Response for a successful PIA SBOM upload."""

    polling_url: HttpUrl
    """DependencyTrack URL to poll for processing status of this upload."""

    model_config = ConfigDict(use_attribute_docstrings=True)


class DependencyTrackUploadPayload(BaseModel):
    """Payload for DependencyTrack SBOM upload."""

    project_name: str = Field(serialization_alias="projectName")
    project_version: str = Field(serialization_alias="projectVersion")
    parent_uuid: str = Field(serialization_alias="parentUUID")
    auto_create: bool = Field(default=True, serialization_alias="autoCreate")
    is_latest: bool = Field(serialization_alias="isLatest")
    bom: str

    def to_dict(self):
        return self.model_dump(by_alias=True)
