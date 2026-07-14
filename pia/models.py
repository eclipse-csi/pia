"""ORM models for projects/workloads/products and Pydantic request models."""

import logging
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl
from sqlalchemy import ForeignKey, Select, String, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

logger = logging.getLogger(__name__)


GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
"""OIDC issuer for GitHub Actions tokens. Constant across all GitHub workloads."""

GITHUB_BASE_URL = "https://github.com"
"""Scheme and host of the GitHub repo URLs accepted when registering workloads."""

JENKINS_ISSUER_BASE_URL = "https://ci.eclipse.org"
"""Scheme and host every Jenkins issuer URL must have."""

JENKINS_OIDC_SUFFIX = "/oidc"
"""Path suffix appended to a Jenkins workload URL to form its OIDC issuer.

Each Eclipse Jenkins project serves its issuer at
``https://ci.eclipse.org/<name>/oidc`` (see docs/DESIGN.md §7.2). Curated
project files list the workload URL (``https://ci.eclipse.org/<name>``); PIA
appends this suffix."""

GITHUB_ALLOWED_EVENT_NAMES = frozenset({"push", "workflow_dispatch"})
"""Allowed values for the GitHub OIDC token's `event_name` claim.

Restricts the OIDC mint to events that require write access to the repo
(i.e. only maintainers can cause one). Excludes triggers like
`pull_request_target`, `workflow_run`, and `issue_comment` that can be
indirectly driven by non-maintainers. Relax on demand."""


class Base(DeclarativeBase):
    """Declarative base class for al ORM models."""


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

    Polymorphic base — see GitHubWorkload and JenkinsWorkload. Uses joined-
    table inheritance: each subclass gets its own table sharing the `id` PK
    with this base table. SQLAlchemy uses the `type` discriminator column to
    instantiate the right subclass when loading rows.
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

    id: Mapped[int] = mapped_column(ForeignKey("workloads.id"), primary_key=True)
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
            f"Github Workload  (project: {self.ef_project_id}, "
            f"repo: {self.repo_owner}/{self.repo_name}, owner id: {self.repo_owner_id})"
        )


class JenkinsWorkload(Workload):
    """Jenkins workload. Each instance has a distinct issuer URL."""

    __tablename__ = "jenkins_workloads"

    id: Mapped[int] = mapped_column(ForeignKey("workloads.id"), primary_key=True)

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
    """DependencyTrack target for SBOM uploads."""

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

    __table_args__ = (
        # DependencyTrack targets (product name plus uuid) are globally unique
        # and map to exactly one EF project. Keeping it globally unique stops
        # two EF projects from pointing at the same DT target, so an upload
        # authorized for one project can never reach another's DT project.
        UniqueConstraint("name", "parent_uuid"),
        # DependencyTrack target names (product name) are unique within an EF
        # project to avoid ambiguity when resolving the target based on the
        # name in the upload payload. They are not globally unique, to allow
        # different EF projects to e.g. upload a product named "cli" or "server".
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


def is_issuer_known(issuer: str) -> bool:
    """Check if issuer is generally known to PIA.

    GitHub: issuer must equal GITHUB_ISSUER
    Jenkins: issuer's scheme and host must equal JENKINS_ISSUER_BASE_URL

    """
    if issuer == GITHUB_ISSUER:
        return True

    parsed = urlparse(issuer)
    return f"{parsed.scheme}://{parsed.hostname}" == JENKINS_ISSUER_BASE_URL


def find_workload_by_claims(
    session: Session, token_claims: dict[str, Any]
) -> Workload | None:
    """Find Workload matching verified token claims.

    GitHub: match by repo_owner, repo_name, repo_owner_id.
    Jenkins: match by exact issuer.
    Returns None if no match.
    """
    issuer = token_claims["iss"]
    logger.info(f"Searching for workload matching issuer '{issuer}' and token claims")

    stmt: Select[Any]
    if issuer == GITHUB_ISSUER:
        repository = token_claims.get("repository", "")
        if "/" not in repository:
            logger.info(
                f"GitHub token missing or malformed 'repository' claim: {repository!r}"
            )
            return None
        repo_owner, repo_name = repository.split("/", 1)
        repo_owner_id = token_claims.get("repository_owner_id")
        stmt = select(GitHubWorkload).where(
            GitHubWorkload.repo_owner == repo_owner,
            GitHubWorkload.repo_name == repo_name,
            GitHubWorkload.repo_owner_id == repo_owner_id,
        )
    else:
        stmt = select(JenkinsWorkload).where(JenkinsWorkload.issuer == issuer)
    return session.execute(stmt).scalar_one_or_none()


def verify_workload_claims(workload: Workload, claims: dict[str, Any]) -> str | None:
    """Workload-type-specific claim verification beyond the workload-match step.

    Returns a human-readable reason on rejection, or None on success.
    """
    if isinstance(workload, GitHubWorkload):
        event_name = claims.get("event_name")
        if event_name not in GITHUB_ALLOWED_EVENT_NAMES:
            return (
                f"GitHub event_name {event_name!r} not in allowlist "
                f"{sorted(GITHUB_ALLOWED_EVENT_NAMES)}"
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


class PiaUploadPayload(BaseModel):
    """Payload for PIA SBOM upload."""

    product_name: str
    """
    Name of product for which the SBOM is produced. This field is required by
    DependencyTrack to aggregate SBOMs by product within a project.
    """

    product_version: str
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

    model_config = ConfigDict(use_attribute_docstrings=True)


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
