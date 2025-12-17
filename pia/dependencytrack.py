"""DependencyTrack API client."""

import requests

from .models import DependencyTrackUploadPayload


class DependencyTrackError(Exception):
    """Raised when DependencyTrack API request fails."""


def upload_sbom(
    url: str,
    api_key: str,
    payload: DependencyTrackUploadPayload,
) -> requests.Response:
    """Upload SBOM to DependencyTrack.

    Args:
        url: API endpoint
        api_key: API key
        payload: SBOM payload to upload

    Returns:
        Response from DependencyTrack API

    Raises:
        DependencyTrackError: If upload fails
    """
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": api_key,
    }

    try:
        response = requests.post(
            url,
            json=payload.to_dict(),
            headers=headers,
        )

        # Return response for caller to handle status code
        return response

    except requests.RequestException as e:
        raise DependencyTrackError(
            f"Failed to upload SBOM to DependencyTrack: {e}"
        ) from e
