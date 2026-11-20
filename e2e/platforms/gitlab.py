"""Eclipse GitLab: runs the `pia-upload` job of a pia-test-workload project.

The pipeline is created via the Pipelines API (`pipeline_source` "api") with
the upload parameters passed as pipeline inputs. The job posts the SBOM to PIA
and stores PIA's response as the `pia-response.json` artifact, which is read
back here.
"""

import json
import time
from typing import Any
from urllib.parse import quote

import pytest
import requests

from . import UploadRequest, UploadResult

GITLAB_URL = "https://gitlab.eclipse.org"
PROJECT_PATH = "eclipsefdn/security/pia-test-workload"
REF = "main"
JOB_NAME = "pia-upload"
ARTIFACT = "pia-response.json"
FINISHED = {"success", "failed", "canceled", "skipped"}


class EclipseGitLab:
    name = "gitlab"
    product = "pia-test-workload-gitlab"

    def __init__(
        self,
        token: str,
        project_path: str = PROJECT_PATH,
        timeout: float = 600,
        interval: float = 10,
    ):
        self.workload_url = f"{GITLAB_URL}/{project_path}"
        self.api = f"{GITLAB_URL}/api/v4/projects/{quote(project_path, safe='')}"
        self.headers = {"PRIVATE-TOKEN": token}
        self.timeout = timeout
        self.interval = interval

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        r = requests.request(
            method, f"{self.api}{path}", headers=self.headers, timeout=30, **kwargs
        )
        if not r.ok:
            pytest.fail(f"GitLab API {method} {path}: HTTP {r.status_code}: {r.text}")
        return r

    def run_upload(self, req: UploadRequest) -> UploadResult:
        pipeline = self._request(
            "POST",
            "/pipeline",
            json={"ref": REF, "inputs": req.inputs()},
        ).json()
        run_url = pipeline["web_url"]

        deadline = time.monotonic() + self.timeout
        while pipeline["status"] not in FINISHED:
            if time.monotonic() > deadline:
                pytest.fail(f"GitLab pipeline did not finish in time: {run_url}")
            time.sleep(self.interval)
            pipeline = self._request("GET", f"/pipelines/{pipeline['id']}").json()

        jobs = self._request("GET", f"/pipelines/{pipeline['id']}/jobs").json()
        job = next((j for j in jobs if j["name"] == JOB_NAME), None)
        if job is None or job["status"] != "success":
            pytest.fail(f"GitLab job {JOB_NAME!r} did not succeed: {run_url}")

        response = json.loads(
            self._request("GET", f"/jobs/{job['id']}/artifacts/{ARTIFACT}").text
        )
        return UploadResult(response["status"], response["body"], run_url)
