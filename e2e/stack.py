"""Bring up and provision the local docker compose stack for e2e tests.

Starts postgres, DependencyTrack and the ngrok tunnel, provisions a
DependencyTrack API key (reusing `scripts/dt_bootstrap.py`), (re)starts pia
with that key, and registers the workloads and products of the given platforms
with `pia create-dt-projects` and `pia sync`. The stack is left running afterwards,
tear it down with `docker compose --profile e2e down`.
"""

import importlib.util
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import requests
import yaml

from pia.sync import resolve_dt_child_uuid

from .platforms import Platform

REPO_ROOT = Path(__file__).resolve().parent.parent
EF_PROJECT = "technology.csi"
DT_PROJECT = "PIA E2E"
PIA_URL = "http://localhost:8000"
NGROK_API_URL = "http://localhost:4040/api/tunnels"
DATABASE_URL = "postgresql://pia:pia@localhost:5432/pia"


@dataclass(frozen=True)
class Stack:
    dt_url: str
    dt_api_key: str
    public_url: str
    dt_project: str

    def product_uuid(self, product: str) -> str:
        return resolve_dt_child_uuid(
            self.dt_url, self.dt_project, product, self.dt_api_key
        )


def _load_dt_bootstrap() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "dt_bootstrap", REPO_ROOT / "scripts" / "dt_bootstrap.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(cmd: list[str], env: dict[str, str] | None = None) -> None:
    subprocess.run(cmd, cwd=REPO_ROOT, env={**os.environ, **(env or {})}, check=True)


def _wait_for(url: str, timeout: float = 60) -> requests.Response:
    deadline = time.monotonic() + timeout
    while True:
        try:
            r = requests.get(url, timeout=5)
            if r.ok:
                return r
        except requests.ConnectionError:
            pass
        if time.monotonic() > deadline:
            raise TimeoutError(f"{url} not ready after {timeout}s")
        time.sleep(2)


def _public_url() -> str:
    tunnels = _wait_for(NGROK_API_URL).json()["tunnels"]
    return next(t["public_url"] for t in tunnels if t["proto"] == "https")


def _write_projects_file(platforms: list[Platform], path: Path) -> None:
    """Register all platforms' workloads and products under one EF project.

    Synced with --allow-db-updates-and-deletions, so it replaces any other
    registrations in the local database.
    """
    project = {
        "id": EF_PROJECT,
        "workloads": [p.workload_url for p in platforms],
        "dependency_track": {
            "project": DT_PROJECT,
            "products": [p.product for p in platforms],
        },
    }
    path.write_text(yaml.safe_dump({"projects": [project]}))


def up(platforms: list[Platform], tmp_dir: Path) -> Stack:
    _run(["docker", "compose", "--profile", "e2e", "up", "-d", "postgres", "dtrack"])

    bootstrap = _load_dt_bootstrap()
    bootstrap.wait_for_api()
    auth = {"Authorization": f"Bearer {bootstrap.ensure_admin_password()}"}
    team_uuid = bootstrap.ensure_team(auth)
    bootstrap.ensure_permissions(auth, team_uuid)
    key = bootstrap.generate_api_key(auth, team_uuid)
    dt_url = bootstrap.DT_URL

    # Recreate pia so it picks up the new DependencyTrack API key.
    _run(
        ["docker", "compose", "up", "-d", "pia"],
        env={"PIA_DEPENDENCY_TRACK_API_KEY": key},
    )
    _wait_for(f"{PIA_URL}/livez")
    _run(["docker", "compose", "--profile", "e2e", "up", "-d", "ngrok"])

    projects_file = str(tmp_dir / "projects.yaml")
    _write_projects_file(platforms, Path(projects_file))
    pia = str(Path(sys.executable).parent / "pia")
    cli_env = {"PIA_DATABASE_URL": DATABASE_URL, "PIA_DEPENDENCY_TRACK_API_KEY": key}
    _run(
        [pia, "create-dt-projects", projects_file, "--dt-url", dt_url],
        env=cli_env,
    )
    _run(
        [pia, "sync", projects_file, "--dt-url", dt_url]
        + ["--allow-db-updates-and-deletions"],
        env=cli_env,
    )

    return Stack(dt_url, key, _public_url(), dt_project=DT_PROJECT)
