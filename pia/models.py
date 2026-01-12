"""Data models with validation and authentication logic."""

from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, RootModel, UrlConstraints

# `preserve_empty_path=True` tells pydantic to not add any trailing slashes,
# to avoid surprising results in `Project.match_issuer`.
HttpsUrl = Annotated[
    HttpUrl, UrlConstraints(allowed_schemes=["https"], preserve_empty_path=True)
]


class Project(BaseModel):
    """Eclipse Foundation Project model."""

    project_id: str
    """
    Eclipse Foundation project ID
    https://www.eclipse.org/projects/handbook/#resources-identifiers
    """

    issuer: HttpsUrl
    """
    Allowed OIDC issuer for this project
    """

    dt_parent_uuid: str
    """
    DependencyTrack project UUID for SBOMs of this project
    """

    required_claims: dict[str, str] = Field(default_factory=dict)
    """
    Map of OIDC claim names and values required in OIDC tokens for this project
    """

    model_config = ConfigDict(use_attribute_docstrings=True)

    def match_issuer(self, issuer: str) -> bool:
        """Verify that issuer matches allowed project issuer."""
        return issuer == str(self.issuer)

    def match_claims(self, token_claims: dict[str, Any]) -> bool:
        """Verify that token claims match required claims for project."""
        for claim_name, expected_value in self.required_claims.items():
            if token_claims.get(claim_name) != expected_value:
                return False

        return True


class Projects(RootModel):
    """List of Eclipse Foundation projects.

    https://www.eclipse.org/projects/handbook/#resources-identifiers
    """

    root: list[Project]

    def has_issuer(self, issuer: str) -> bool:
        """Check if any project has the given issuer."""
        return any(project.match_issuer(issuer) for project in self.root)

    def find_project_by_claims(self, token_claims: dict[str, Any]) -> Project | None:
        """Find project by matching verified token claims.

        Returns Project if found, None otherwise.
        A project matches if issuer matches AND all required_claims match.
        """
        issuer = token_claims["iss"]
        for project in self.root:
            if project.match_issuer(issuer) and project.match_claims(token_claims):
                return project
        return None

    @classmethod
    def from_yaml_file(cls, path: str) -> "Projects":
        """Load Projects from YAML file."""
        with open(path) as f:
            config = yaml.safe_load(f)

        return cls.model_validate(config)


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

    model_config = ConfigDict(use_attribute_docstrings=True)


class DependencyTrackUploadPayload(BaseModel):
    """Payload for DependencyTrack SBOM upload."""

    project_name: str = Field(serialization_alias="projectName")
    project_version: str = Field(serialization_alias="projectVersion")
    parent_uuid: str = Field(serialization_alias="parentUUID")
    auto_create: bool = Field(default=True, serialization_alias="autoCreate")
    bom: str

    def to_dict(self):
        return self.model_dump(by_alias=True)
