"""Read-side DependencyTrack client for e2e assertions."""

import time
from typing import Any

import pytest
import requests


class DependencyTrack:
    def __init__(self, url: str, api_key: str):
        self.url = url
        self.headers = {"X-Api-Key": api_key}

    def _get(self, path: str, **params: str) -> Any:
        r = requests.get(
            f"{self.url}/api/v1{path}", headers=self.headers, params=params, timeout=15
        )
        r.raise_for_status()
        return r.json()

    def wait_processed(self, polling_url: str, timeout: float = 120) -> None:
        """Wait until the BOM behind a PIA `polling_url` has been processed.

        Only the token is taken from `polling_url`, as its host is the
        DependencyTrack address as seen from the pia container.
        """
        token = polling_url.rstrip("/").rsplit("/", 1)[-1]
        deadline = time.monotonic() + timeout
        while self._get(f"/bom/token/{token}")["processing"]:
            if time.monotonic() > deadline:
                pytest.fail(f"DependencyTrack did not process BOM {token} in time")
            time.sleep(2)

    def project(self, name: str, version: str) -> dict[str, Any]:
        # The lookup response omits `parent`, so fetch the full project by UUID
        uuid = self._get("/project/lookup", name=name, version=version)["uuid"]
        return self._get(f"/project/{uuid}")

    def components(self, project_uuid: str) -> list[dict[str, Any]]:
        return self._get(f"/component/project/{project_uuid}")
