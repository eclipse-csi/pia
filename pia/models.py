"""Data models with validation and authentication logic."""

from typing import Any

import yaml
from pydantic import BaseModel, Field, HttpUrl, field_validator


class Project(BaseModel):
    issuer: HttpUrl
    dt_parent_uuid: str
    required_claims: dict[str, str] | None = Field(default_factory=dict)

    @field_validator("issuer")
    @classmethod
    def validate_https(cls, v: HttpUrl) -> HttpUrl:
        """Validate that issuer URL uses HTTPS."""
        if v.scheme != "https":
            raise ValueError("issuer must be HTTPS URL")
        return v

    def is_issuer_allowed(self, issuer: str) -> bool:
        """Check if issuer is allowed for project."""
        # Normalize URLs for comparison using HttpUrl
        # This ensures consistent trailing slash handling
        try:
            normalized_issuer = str(HttpUrl(issuer))
            return str(self.issuer) == normalized_issuer

        except Exception:
            # If issuer is invalid, comparison fails
            return False

    def match_claims(self, token_claims: dict[str, Any]) -> bool:
        """Verify that token claims match required claims for project."""
        for claim_name, expected_value in self.required_claims.items():
            if token_claims.get(claim_name) != expected_value:
                return False

        return True


class AllowList(BaseModel):
    projects: dict[str, Project]

    def find_project(self, project_id: str) -> Project | None:
        """Find project in AllowList by project ID."""
        return self.projects.get(project_id, None)

    @classmethod
    def from_yaml_file(cls, path: str) -> "AllowList":
        """Load YAML project AllowList file."""
        with open(path) as f:
            config_dict = yaml.safe_load(f)

        return cls.model_validate(config_dict)


class PIAUploadPayload(BaseModel):
    """Payload for PIA SBOM upload."""

    project_id: str
    product_name: str
    product_version: str
    bom: str
    token: str


class DependencyTrackUploadPayload(BaseModel):
    """Payload for DependencyTrack SBOM upload."""

    project_name: str = Field(serialization_alias="projectName")
    project_version: str = Field(serialization_alias="projectVersion")
    parent_uuid: str = Field(serialization_alias="parentUUID")
    auto_create: bool = Field(default=True, serialization_alias="autoCreate")
    bom: str

    def to_dict(self):
        return self.model_dump(by_alias=True)
