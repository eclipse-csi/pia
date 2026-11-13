"""Fixtures for end-to-end tests against the local stack and real CI services.

Run with `make test-e2e`. Requires Docker, NGROK_AUTHTOKEN (for the public
tunnel to the local pia) and per-platform credentials; tests for platforms
without credentials are skipped.
"""

import base64
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from . import stack as stack_mod
from .dependencytrack import DependencyTrack
from .platforms import Platform
from .platforms.github import GitHubActions
from .platforms.gitlab import EclipseGitLab

DATA = Path(__file__).resolve().parent / "data"


def _gitlab() -> Platform | None:
    token = os.environ.get("PIA_E2E_GITLAB_TOKEN")
    return EclipseGitLab(token) if token else None


def _github() -> Platform | None:
    token = os.environ.get("PIA_E2E_GITHUB_TOKEN")
    repo = os.environ.get("PIA_E2E_GITHUB_REPO")
    return GitHubActions(token, repo) if token and repo else None


# Platform name -> factory, which returns None if credentials are missing.
PLATFORMS: dict[str, Callable[[], Platform | None]] = {
    "gitlab": _gitlab,
    "github": _github,
}


@pytest.fixture(scope="session")
def available_platforms() -> dict[str, Platform]:
    platforms = {name: factory() for name, factory in PLATFORMS.items()}
    return {name: p for name, p in platforms.items() if p is not None}


# Session-scoped and requested before `stack`, so that a missing platform
# credential skips before the stack is started.
@pytest.fixture(scope="session")
def platform(
    request: pytest.FixtureRequest, available_platforms: dict[str, Platform]
) -> Platform:
    if request.param not in available_platforms:
        pytest.skip(f"no credentials for platform {request.param!r}")
    return available_platforms[request.param]


@pytest.fixture(scope="session")
def stack(
    available_platforms: dict[str, Platform], tmp_path_factory: pytest.TempPathFactory
) -> stack_mod.Stack:
    if not os.environ.get("NGROK_AUTHTOKEN"):
        pytest.skip("NGROK_AUTHTOKEN not set")
    return stack_mod.up(
        list(available_platforms.values()), tmp_path_factory.mktemp("stack")
    )


@pytest.fixture(scope="session")
def dt(stack: stack_mod.Stack) -> DependencyTrack:
    return DependencyTrack(stack.dt_url, stack.dt_api_key)


@pytest.fixture(scope="session")
def sbom_b64() -> str:
    return base64.b64encode((DATA / "sbom.cdx.json").read_bytes()).decode()
