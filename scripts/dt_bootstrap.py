#!/usr/bin/env python3
"""Bootstrap the local DependencyTrack for development.

Waits for the DependencyTrack API (from docker-compose) to come up, changes the
default admin password on first run, provisions a team with the permissions the
PIA app and `pia sync` need and generates and prints an API token.

Usage:
    uv run python scripts/dt_bootstrap.py

Targets the local docker-compose DependencyTrack only; the URL and admin
credentials are hard-coded for that disposable instance.
"""

import sys
import time

import requests

DT_URL = "http://localhost:8080"
ADMIN_USER = "admin"
DEFAULT_PASSWORD = "admin"

# Local-dev only: DependencyTrack from docker-compose is disposable and never
# exposed. Hard-coded (not env-configurable) to keep the local scope unambiguous;
# stable so re-runs can log back in.
NEW_PASSWORD = "PiaLocal123!"  # NOSONAR
TEAM_NAME = "pia-local"
# Permissions needed by `pia sync` (VIEW_PORTFOLIO to query projects) and by the
# PIA app when uploading SBOMs against this local instance.
TEAM_PERMISSIONS = [
    "VIEW_PORTFOLIO",
    "PORTFOLIO_MANAGEMENT",
    "PROJECT_CREATION_UPLOAD",
    "BOM_UPLOAD",
]


def log(msg: str) -> None:
    print(f"[dt-bootstrap] {msg}", flush=True)


def wait_for_api(timeout: int = 240) -> None:
    log(f"Waiting for DependencyTrack at {DT_URL} (up to {timeout}s)...")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{DT_URL}/api/version", timeout=5)
            if r.ok:
                log(f"DependencyTrack {r.json().get('version', '?')} is up.")
                return
        except requests.RequestException:
            pass
        time.sleep(5)
    sys.exit(f"DependencyTrack did not become ready within {timeout}s.")


def login(password: str) -> str | None:
    """Return a JWT for admin with the given password, or None if it fails."""
    r = requests.post(
        f"{DT_URL}/api/v1/user/login",
        data={"username": ADMIN_USER, "password": password},
        timeout=15,
    )
    if r.status_code == 200:
        return r.text.strip().strip('"')
    return None


def ensure_admin_password() -> str:
    """Log in as admin, forcing the first-run password change if needed."""
    token = login(NEW_PASSWORD)
    if token:
        log("Logged in as admin (password already set).")
        return token

    log("First run: changing the default admin password.")
    r = requests.post(
        f"{DT_URL}/api/v1/user/forceChangePassword",
        data={
            "username": ADMIN_USER,
            "password": DEFAULT_PASSWORD,
            "newPassword": NEW_PASSWORD,
            "confirmPassword": NEW_PASSWORD,
        },
        timeout=15,
    )
    if r.status_code not in (200, 204):
        sys.exit(
            "Could not change the admin password "
            f"(HTTP {r.status_code}: {r.text!r}). If the local DependencyTrack "
            "already has a non-default password, reset it with "
            "`docker compose down -v` and re-run."
        )
    token = login(NEW_PASSWORD)
    if not token:
        sys.exit("Password changed but login still failed.")
    return token


def ensure_team(auth: dict[str, str]) -> str:
    """Return the UUID of the TEAM_NAME team, creating it if necessary."""
    r = requests.get(f"{DT_URL}/api/v1/team", headers=auth, timeout=15)
    r.raise_for_status()
    for team in r.json():
        if team.get("name") == TEAM_NAME:
            return team["uuid"]
    r = requests.put(
        f"{DT_URL}/api/v1/team", headers=auth, json={"name": TEAM_NAME}, timeout=15
    )
    r.raise_for_status()
    log(f"Created team {TEAM_NAME!r}.")
    return r.json()["uuid"]


def ensure_permissions(auth: dict[str, str], team_uuid: str) -> None:
    for perm in TEAM_PERMISSIONS:
        r = requests.post(
            f"{DT_URL}/api/v1/permission/{perm}/team/{team_uuid}",
            headers=auth,
            timeout=15,
        )
        # 200 = added, 304 = already present.
        if r.status_code not in (200, 304):
            log(f"Warning: could not grant {perm} (HTTP {r.status_code}).")
    log(f"Granted permissions: {', '.join(TEAM_PERMISSIONS)}.")


def generate_api_key(auth: dict[str, str], team_uuid: str) -> str:
    r = requests.put(f"{DT_URL}/api/v1/team/{team_uuid}/key", headers=auth, timeout=15)
    r.raise_for_status()
    body = r.json()
    # DependencyTrack returns {"key": "..."} (older) or {"publicId":..,"key":..}.
    return body["key"] if isinstance(body, dict) else str(body)


def main() -> None:
    wait_for_api()
    jwt = ensure_admin_password()
    auth = {"Authorization": f"Bearer {jwt}"}

    team_uuid = ensure_team(auth)
    ensure_permissions(auth, team_uuid)
    key = generate_api_key(auth, team_uuid)

    print("\n" + "=" * 70)
    print("DependencyTrack is ready.")
    print(f"  API:   {DT_URL}")
    print(f"  Admin: {ADMIN_USER} / {NEW_PASSWORD}")
    print(f"  Token: {key}")
    print("=" * 70)
    print("\nTry the sync CLI locally:\n")
    print("  export PIA_DATABASE_URL=postgresql://pia:pia@localhost:5432/pia")
    print(f"  export PIA_DEPENDENCY_TRACK_API_KEY={key}")
    print(f"  uv run pia sync projects.local.yaml --dt-url {DT_URL} --dry-run\n")


if __name__ == "__main__":
    main()
