"""Application settings."""

from pydantic import HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables

    e.g. PIA_DEPENDENCY_TRACK_API_KEY -> dependency_track_api_key
    """

    dependency_track_api_key: str
    """
    DependencyTrack API Key
    https://docs.dependencytrack.org/integrations/rest-api/
    """
    projects_path: str
    """
    Path to projects.yaml
    """

    expected_audience: str = "pia.eclipse.org"
    """
    Expected value for "aud" claim in all OIDC tokens
    """

    dependency_track_url: HttpUrl = "https://sbom.eclipse.org/api/v1/bom"  # type: ignore[assignment]
    """
    DependencyTrack SBOM upload URL
    """

    model_config = SettingsConfigDict(env_prefix="PIA_", use_attribute_docstrings=True)
