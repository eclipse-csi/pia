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
from .platforms.gitlab import EclipseGitLab

DATA = Path(__file__).resolve().parent / "data"


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} not set")
    return value


# Platform name -> factory; a factory skips if its credentials are missing.
PLATFORMS: dict[str, Callable[[], Platform]] = {
    "gitlab": lambda: EclipseGitLab(_require_env("PIA_E2E_GITLAB_TOKEN")),
}


@pytest.fixture(scope="session")
def stack() -> stack_mod.Stack:
    _require_env("NGROK_AUTHTOKEN")
    return stack_mod.up()


@pytest.fixture(scope="session")
def dt(stack: stack_mod.Stack) -> DependencyTrack:
    return DependencyTrack(stack.dt_url, stack.dt_api_key)


# Session-scoped and requested before `stack`, so that a missing platform
# credential skips before the stack is started.
@pytest.fixture(scope="session")
def platform(request: pytest.FixtureRequest) -> Platform:
    return PLATFORMS[request.param]()


@pytest.fixture(scope="session")
def sbom_b64() -> str:
    return base64.b64encode((DATA / "sbom.cdx.json").read_bytes()).decode()
