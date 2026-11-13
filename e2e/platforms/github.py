"""GitHub Actions: runs the `pia-upload` workflow of a pia-test-workload repo.

The workflow is dispatched (`event_name` "workflow_dispatch") with the upload
parameters as workflow inputs. The workflow posts the SBOM to PIA and stores
PIA's response as the `pia-response` artifact, which is read back here.

The dispatch API does not return the run it created, so the run is found by its
`run-name`, which the workflow sets to the (unique) product version.
"""

import io
import json
import time
import zipfile
from typing import Any

import pytest
import requests

from . import UploadRequest, UploadResult

GITHUB_API_URL = "https://api.github.com"
REF = "main"
WORKFLOW = "pia-upload.yml"
ARTIFACT = "pia-response"
ARTIFACT_FILE = "pia-response.json"


class GitHubActions:
    name = "github"
    product = "pia-test-workload-github"

    def __init__(
        self, token: str, repo: str, timeout: float = 600, interval: float = 10
    ):
        self.workload_url = f"https://github.com/{repo}"
        self.api = f"{GITHUB_API_URL}/repos/{repo}"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.timeout = timeout
        self.interval = interval

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        r = requests.request(
            method, f"{self.api}{path}", headers=self.headers, timeout=30, **kwargs
        )
        if not r.ok:
            pytest.fail(f"GitHub API {method} {path}: HTTP {r.status_code}: {r.text}")
        return r

    def _find_run(self, run_name: str) -> dict[str, Any] | None:
        runs = self._request(
            "GET",
            f"/actions/workflows/{WORKFLOW}/runs",
            params={"event": "workflow_dispatch", "per_page": "20"},
        ).json()["workflow_runs"]
        return next((r for r in runs if r["display_title"] == run_name), None)

    def run_upload(self, req: UploadRequest) -> UploadResult:
        self._request(
            "POST",
            f"/actions/workflows/{WORKFLOW}/dispatches",
            json={"ref": REF, "inputs": req.inputs()},
        )

        deadline = time.monotonic() + self.timeout
        run = None
        while run is None or run["status"] != "completed":
            if time.monotonic() > deadline:
                where = run["html_url"] if run else f"{self.workload_url}/actions"
                pytest.fail(f"GitHub workflow run did not finish in time: {where}")
            time.sleep(self.interval)
            if run is None:
                run = self._find_run(req.product_version)
            else:
                run = self._request("GET", f"/actions/runs/{run['id']}").json()

        run_url = run["html_url"]
        if run["conclusion"] != "success":
            pytest.fail(f"GitHub workflow run did not succeed: {run_url}")

        artifacts = self._request("GET", f"/actions/runs/{run['id']}/artifacts").json()
        artifact = next(
            (a for a in artifacts["artifacts"] if a["name"] == ARTIFACT), None
        )
        if artifact is None:
            pytest.fail(f"GitHub workflow run has no {ARTIFACT!r} artifact: {run_url}")

        # Redirects to a pre-signed storage URL; requests drops the auth header
        # on the cross-host redirect.
        archive = self._request("GET", f"/actions/artifacts/{artifact['id']}/zip")
        with zipfile.ZipFile(io.BytesIO(archive.content)) as zf:
            response = json.loads(zf.read(ARTIFACT_FILE))
        return UploadResult(response["status"], response["body"], run_url)
