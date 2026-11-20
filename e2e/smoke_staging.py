"""Smoke test SBOM uploads from the CI test workloads to a deployed PIA.

Triggers the `pia-upload` job of the GitLab and GitHub pia-test-workload repos
against a deployed PIA (default: pia-staging.eclipse.org), checks that PIA
accepted the upload, and optionally waits for DependencyTrack to process it.

Reuses the e2e platforms, data and DependencyTrack client, but nothing of the
local e2e stack. See docs/smoke-test-staging.md for setup and usage:

    uv run python -m e2e.smoke_staging --help
"""

import argparse
import base64
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import requests

from .dependencytrack import DependencyTrack
from .platforms import Platform, UploadRequest
from .platforms.github import GitHubActions
from .platforms.gitlab import EclipseGitLab

WORKLOAD_NAME = "pia-test-workload"
SBOM = Path(__file__).resolve().parent / "data" / "sbom.cdx.json"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke test SBOM uploads from the CI test workloads to a "
        "deployed PIA.",
        epilog="Secrets are read from the environment: PIA_SMOKE_GITLAB_TOKEN, "
        "PIA_SMOKE_GITHUB_TOKEN and (optional) PIA_SMOKE_DT_API_KEY.",
    )
    parser.add_argument(
        "--platform",
        action="append",
        choices=["gitlab", "github"],
        help="platform to test, repeatable (default: all with credentials)",
    )
    parser.add_argument("--pia-url", default="https://pia-staging.eclipse.org")
    parser.add_argument(
        "--audience",
        default="pia-staging.eclipse.org",
        help="OIDC token audience expected by PIA (default: %(default)s)",
    )
    parser.add_argument(
        "--dt-url",
        default="https://sbom-staging.eclipse.org",
        help="DependencyTrack base URL to check BOM processing on, used instead "
        "of the host in PIA's polling_url (default: %(default)s)",
    )
    parser.add_argument(
        "--gitlab-group",
        default="eclipsefdn/security",
        help=f"GitLab group of the {WORKLOAD_NAME} project (default: %(default)s)",
    )
    parser.add_argument(
        "--github-owner", help=f"GitHub owner of the {WORKLOAD_NAME} repo"
    )
    parser.add_argument(
        "--gitlab-product",
        default=EclipseGitLab.product,
        help="DependencyTrack product (default: %(default)s)",
    )
    parser.add_argument(
        "--github-product",
        default=GitHubActions.product,
        help="DependencyTrack product (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=600,
        help="max seconds per CI run (default: %(default)s)",
    )
    return parser.parse_args()


def _platforms(args: argparse.Namespace) -> tuple[dict[str, Platform], list[str]]:
    """Return platforms to test and reasons for skipped ones."""
    platforms: dict[str, Platform] = {}
    missing: dict[str, str] = {}

    gitlab_token = os.environ.get("PIA_SMOKE_GITLAB_TOKEN")
    if gitlab_token:
        platforms["gitlab"] = EclipseGitLab(
            gitlab_token,
            project_path=f"{args.gitlab_group}/{WORKLOAD_NAME}",
            timeout=args.timeout,
        )
    else:
        missing["gitlab"] = "PIA_SMOKE_GITLAB_TOKEN not set"

    github_token = os.environ.get("PIA_SMOKE_GITHUB_TOKEN")
    if github_token and args.github_owner:
        platforms["github"] = GitHubActions(
            github_token, f"{args.github_owner}/{WORKLOAD_NAME}", timeout=args.timeout
        )
    else:
        missing["github"] = "PIA_SMOKE_GITHUB_TOKEN or --github-owner not set"

    if args.platform:
        for name in args.platform:
            if name in missing:
                sys.exit(f"Cannot test {name}: {missing[name]}")
        platforms = {n: p for n, p in platforms.items() if n in args.platform}
        return platforms, []

    return platforms, [f"SKIP {name}: {reason}" for name, reason in missing.items()]


def _smoke(
    platform: Platform,
    product: str,
    args: argparse.Namespace,
    bom_b64: str,
    dt: DependencyTrack | None,
) -> bool:
    version = f"smoke-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"
    print(
        f"{platform.name}: uploading {product} {version} from {platform.workload_url}"
    )
    try:
        result = platform.run_upload(
            UploadRequest(args.pia_url, product, version, bom_b64, args.audience)
        )
        print(f"{platform.name}: run {result.run_url}")
        body = result.body
        if (
            result.status != 200
            or not isinstance(body, dict)
            or "polling_url" not in body
        ):
            print(f"FAIL {platform.name}: PIA returned {result.status}: {result.body}")
            return False

        if dt:
            print(f"{platform.name}: waiting for DependencyTrack at {dt.url}")
            dt.wait_processed(body["polling_url"])
            print(f"PASS {platform.name}: uploaded and processed")
        else:
            print(f"PASS {platform.name}: uploaded (processing not checked)")
        return True

    except (pytest.fail.Exception, requests.RequestException) as e:
        print(f"FAIL {platform.name}: {e}")
        return False


def main() -> None:
    args = _parse_args()
    platforms, skipped = _platforms(args)
    for line in skipped:
        print(line)
    if not platforms:
        print("Nothing to test.")
        return

    try:
        requests.get(f"{args.pia_url}/livez", timeout=15).raise_for_status()
    except requests.RequestException as e:
        sys.exit(f"FAIL: PIA at {args.pia_url} is not up: {e}")

    dt_api_key = os.environ.get("PIA_SMOKE_DT_API_KEY")
    dt = DependencyTrack(args.dt_url, dt_api_key) if dt_api_key else None
    bom_b64 = base64.b64encode(SBOM.read_bytes()).decode()
    products = {"gitlab": args.gitlab_product, "github": args.github_product}

    results = [
        _smoke(platform, products[name], args, bom_b64, dt)
        for name, platform in platforms.items()
    ]
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
