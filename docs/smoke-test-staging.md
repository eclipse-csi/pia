# Staging Smoke Test

`e2e/smoke_staging.py` checks that a deployed PIA, by default
[pia-staging.eclipse.org](https://pia-staging.eclipse.org), accepts SBOM uploads
from real CI workloads on Eclipse GitLab and GitHub Actions.

For each platform it triggers the `pia-upload` job of a `pia-test-workload`
repository, which requests an OIDC token and uploads a dummy SBOM to PIA. The
script then checks that:

1. the CI run succeeded, and PIA responded with `200` and a `polling_url`, and
2. *(optional, with a DependencyTrack API key)* DependencyTrack finished
   processing the uploaded SBOM.

PIA's `polling_url` points to the DependencyTrack address configured in PIA,
which is not reachable from outside the deployment
([#66](https://github.com/eclipse-csi/pia/issues/66)). The script therefore
takes only the token from it, and polls the DependencyTrack given by `--dt-url`
(default: `https://sbom-staging.eclipse.org`).

The script reuses the CI platform clients, test SBOM and CI configs of the
[end-to-end tests](../README.md#end-to-end-tests), but none of their local
stack.

## One-time Setup (out of band)

### 1. Staging deployment

- PIA version with Eclipse GitLab support, including `api` in the allowed
  GitLab `pipeline_source` values (the script starts GitLab pipelines via the
  Pipelines API).
- `PIA_EXPECTED_AUDIENCE=pia-staging.eclipse.org`, or whatever is passed as
  `--audience`.
- Outbound access from PIA to `https://gitlab.eclipse.org` and
  `https://token.actions.githubusercontent.com`, for OIDC discovery and JWKS.

### 2. GitLab test project

The project is `eclipsefdn/security/pia-test-workload` on
gitlab.eclipse.org. Pass `--gitlab-group` for another group.

1. Create it if it doesn't exist yet.
2. Commit `e2e/pia-test-workload.gitlab-ci.yml` to the project's `main` branch
   as `.gitlab-ci.yml`.

### 3. GitHub test repository

The repository is `<owner>/pia-test-workload`, with `<owner>` passed as
`--github-owner`.

1. Create it if it doesn't exist yet. See
   [End-to-end Tests](../README.md#end-to-end-tests).
2. Commit `e2e/pia-test-workload.pia-upload.yml` to its `main` branch as
   `.github/workflows/pia-upload.yml`.

### 4. Register workloads and provision DependencyTrack on staging

Add both workloads and their DependencyTrack products to the projects file
that staging is synced from, for example:

```yaml
projects:
  - id: technology.csi
    workloads:
      - https://gitlab.eclipse.org/eclipsefdn/security/pia-test-workload
      - https://github.com/<owner>/pia-test-workload
    dependency_track:
      project: "PIA Smoke Test"
      products: [pia-test-workload-gitlab, pia-test-workload-github]
```

> [!WARNING]
> `pia sync` reconciles the whole database with the file. Add these entries to
> the existing staging projects file rather than syncing a file with only
> these entries.

The product names must match `--gitlab-product` and `--github-product`. The
defaults are `pia-test-workload-gitlab` and `pia-test-workload-github`. Then
provision and sync:

```shell
export PIA_DATABASE_URL=<staging database URL>
export PIA_DEPENDENCY_TRACK_API_KEY=<staging DependencyTrack API key>
uv run pia create-dt-projects <projects file> --dt-url https://sbom-staging.eclipse.org
uv run pia sync <projects file> --dt-url https://sbom-staging.eclipse.org --dry-run
uv run pia sync <projects file> --dt-url https://sbom-staging.eclipse.org
```

### 5. Tokens

| Variable | What | Permissions |
| --- | --- | --- |
| `PIA_SMOKE_GITLAB_TOKEN` | GitLab fine-grained personal access token (or project access token with role Developer and scope `api`) | On the GitLab test project: "Pipeline: Create", "Pipeline: Read", "Job: Read", "Job Artifact: Read" |
| `PIA_SMOKE_GITHUB_TOKEN` | GitHub fine-grained personal access token, limited to the test repository | "Actions: Read and write" |
| `PIA_SMOKE_DT_API_KEY` *(optional)* | Staging DependencyTrack API key | Read BOM processing status (`BOM_UPLOAD`) |

## Usage

From a checkout of this repository:

```shell
export PIA_SMOKE_GITLAB_TOKEN=...
export PIA_SMOKE_GITHUB_TOKEN=...
export PIA_SMOKE_DT_API_KEY=...   # optional
uv run python -m e2e.smoke_staging --github-owner <owner>
```

- Platforms without credentials are skipped. To require a platform, select it
  with `--platform gitlab` or `--platform github`; the option is repeatable.
- Other targets: `--pia-url`, `--audience` and `--dt-url`. See `--help` for
  all options and defaults.
- Each run uploads a new product version `smoke-<UTC time>-<random>`, so
  results never come from an earlier run.
- A CI run can take a few minutes if runners are busy. `--timeout` limits
  the wait per run (default: 600 seconds).

Example output:

```
gitlab: uploading pia-test-workload-gitlab smoke-20261113T101500Z-3f9a1c from https://gitlab.eclipse.org/eclipsefdn/security/pia-test-workload
gitlab: run https://gitlab.eclipse.org/eclipsefdn/security/pia-test-workload/-/pipelines/...
gitlab: waiting for DependencyTrack at https://sbom-staging.eclipse.org
PASS gitlab: uploaded and processed
github: uploading pia-test-workload-github smoke-20261113T101702Z-b2e04d from https://github.com/<owner>/pia-test-workload
github: run https://github.com/<owner>/pia-test-workload/actions/runs/...
FAIL github: PIA returned 401: {'detail': '...'}
```

The script exits with `1` if any tested platform fails, and with `0`
otherwise, including when all platforms are skipped.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| PIA `401`, token audience invalid | `--audience` doesn't match staging's `PIA_EXPECTED_AUDIENCE`, or the test repo still has a CI config without the `audience` input (step 2 or 3) |
| PIA `401`, no matching workload | Workload not synced on staging, or stale: the GitLab project was renamed or re-created, or the GitHub owner changed (step 4) |
| PIA `401`, no matching DependencyTrack project | Product not provisioned, or product name doesn't match `--gitlab-product` or `--github-product` (step 4) |
| PIA `401`, `pipeline_source` or `event_name` not in allowlist | Staging runs a PIA version without `api` pipeline support (step 1) |
| GitLab or GitHub API `403` | Missing token permission; the error names it (step 5) |
| CI run failed, or the artifact is missing | The CI config in the test repo is outdated or broken; check the run URL |
| Run not found, or timeout | Runners are busy (raise `--timeout`), or the GitHub workflow isn't on `main` |
| DependencyTrack `401` or `403` | `PIA_SMOKE_DT_API_KEY` missing the permission, or wrong `--dt-url` |
