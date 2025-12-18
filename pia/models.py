"""Data models with validation and authentication logic."""

from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, UrlConstraints

# `preserve_empty_path=True` tells pydantic to not add any trailing slashes,
# to avoid surprising results in `Project.match_issuer`.
HttpsUrl = Annotated[
    HttpUrl, UrlConstraints(allowed_schemes=["https"], preserve_empty_path=True)
]


class BaseConfigModel(BaseModel):
    model_config = ConfigDict(use_attribute_docstrings=True)


class Project(BaseConfigModel):
    """Eclipse Foundation Project model."""

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

    def match_issuer(self, issuer: str) -> bool:
        """Verify that issuer matches allowed project issuer."""
        return issuer == str(self.issuer)

    def match_claims(self, token_claims: dict[str, Any]) -> bool:
        """Verify that token claims match required claims for project."""
        for claim_name, expected_value in self.required_claims.items():
            if token_claims.get(claim_name) != expected_value:
                return False

        return True


class Projects(BaseConfigModel):
    """Projects for Eclipse Foundation projects."""

    projects: dict[str, Project]
    """
    Map of Eclipse Foundation project IDs to Projects
    https://www.eclipse.org/projects/handbook/#resources-identifiers
    """

    def find_project(self, project_id: str) -> Project | None:
        """Find project in Projects by project ID."""
        return self.projects.get(project_id, None)

    @classmethod
    def from_yaml_file(cls, path: str) -> "Projects":
        """Load Projects form YAML file."""
        with open(path) as f:
            config_dict = yaml.safe_load(f)

        return cls.model_validate(config_dict)


class PiaUploadPayload(BaseConfigModel):
    """Payload for PIA SBOM upload."""

    project_id: str
    """
    Eclipse Foundation project ID
    https://www.eclipse.org/projects/handbook/#resources-identifiers
    """

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

    token: str
    """
    OIDC token used to authenticate PIA SBOM upload
    """


class DependencyTrackUploadPayload(BaseModel):
    """Payload for DependencyTrack SBOM upload."""

    project_name: str = Field(serialization_alias="projectName")
    project_version: str = Field(serialization_alias="projectVersion")
    parent_uuid: str = Field(serialization_alias="parentUUID")
    auto_create: bool = Field(default=True, serialization_alias="autoCreate")
    bom: str

    def to_dict(self):
        return self.model_dump(by_alias=True)
