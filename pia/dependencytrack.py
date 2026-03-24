"""DependencyTrack API client."""

import logging

import requests

from .models import DependencyTrackUploadPayload

logger = logging.getLogger(__name__)


class DependencyTrackError(Exception):
    """Raised when DependencyTrack API request fails."""


def upload_sbom(
    url: str,
    api_key: str,
    payload: DependencyTrackUploadPayload,
) -> requests.Response:
    """Upload SBOM to DependencyTrack and return full response.
    Raise DependencyTrackError, if upload fails.
    """
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
    }

    try:
        logger.info(f"Uploading SBOM to DependencyTrack at {url}")
        response = requests.put(
            url,
            json=payload.to_dict(),
            headers=headers,
        )
        logger.info(f"DependencyTrack responded with status {response.status_code}")
        return response

    except requests.RequestException as e:
        raise DependencyTrackError(
            f"Failed to upload SBOM to DependencyTrack: {e}"
        ) from e
