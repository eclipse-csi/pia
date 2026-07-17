# PIA - Project Identity Authority

## 1. Overview

### 1.1 Purpose

PIA (Project Identity Authority) is an authentication broker for Eclipse
Foundation projects. It allows projects to publish artifacts, and to proof that
the artifact came from the project's build infrastructure, using OpenID Connect
(OIDC).

In the initial use case, described in this document, PIA serves as intermediary
between Eclipse build infrastructure (GitHub Actions, Jenkins Pipelines) and
the Eclipse DependencyTrack registry. This enables project-level access control
for SBOM uploads to DependencyTrack. Later, PIA may extend to other use cases that
benefit from this authentication.

### 1.2 Problem Statement

DependencyTrack lacks project-level access control:
- Any team with upload permissions can publish SBOMs for all projects
- Shared secrets management is complex and error-prone
- Workarounds exist but are restricted to GitHub Actions

### 1.3 Solution

PIA implements a "Trusted Publishing" architecture using OIDC to:
- Authenticate publishers using short-lived identity tokens
- Verify project ownership through Identity Provider claims
- Eliminate need for long-lived credentials and manual secrets management
  between build infrastructure and DependencyTrack
- Support multiple build platforms (GitHub Actions, Jenkins, extensible to others)
- Provide a scalable architecture (extensible to other artifacts and registries)

## 2. Architecture

### 2.1 Components

```mermaid
sequenceDiagram
    participant Publisher as Publisher<br/>(GHA, Jenkins Pipeline)
    participant IdP as Identity Provider<br/>(GitHub, Jenkins Controller)
    participant PIA as PIA<br/>
    participant dp as DependencyTrack<br/>

    Publisher->>IdP: 1. Request ID token
    IdP->>Publisher: 2. Return ID token
    Publisher->>PIA: 3. Post SBOM + token
    PIA->>IdP: 4. Request OIDC config
    IdP->>PIA: 5. Return OIDC config
    PIA->>IdP: 6. Request JWKs
    IdP->>PIA: 7. Return JWKs
    PIA->>PIA: 8. Authenticate
    Note over PIA: - Verify token<br/>- Match claims with projects database
    PIA->>dp: 9. Upload SBOM
    dp-->>PIA: Success
    PIA-->>Publisher: Success
```

#### Publisher
- GitHub Action workflow or Jenkins Pipeline
- Generates SBOMs
- Requests identity token from its Identity Provider
- Sends SBOM + token to PIA

#### Identity Provider
- **GitHub**: Central OIDC provider (provided by GitHub)
- **Jenkins**: Per-instance OIDC Provider (enabled via plugin)
- Issues cryptographically signed JWT tokens with claims about publisher identity
- Serves OIDC configuration and public keys from well known location

#### PIA
- Provides REST API for SBOM upload
- Verifies identity tokens using OIDC discovery protocol
- Authenticates SBOM based on OIDC claims and internal projects database
- Publishes SBOM to DependencyTrack on behalf of authenticated projects

#### DependencyTrack
- Receives SBOM from PIA after successful authentication

### 2.2 Trust Relationships

1. **Identity Provider** trusts **Publisher** because:
   - Each GitHub Publisher has a built-in auth token for the central GitHub
     Identity Provider (managed by GitHub)
   - Each Jenkins Publisher has its own Identity Provider running on the same
     Jenkins instance (managed by Eclipse Foundation)
2. **PIA** trusts **Identity Provider** because PIA has a projects database for
   Identity Provider (issuer) URLs (managed by Eclipse Foundation)
3. **DependencyTrack** trusts **PIA** because PIA has an auth token for
   the DependencyTrack API (managed by Eclipse Foundation)

## 3. Authentication Flow

### 3.1 Detailed Flow

1. **Token Request**: Publisher requests ID token from Identity Provider

   - GitHub: Uses `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
   - Jenkins: Uses credentials binding plugin with pre-configured credential

2. **Token Issuance**: Identity Provider returns JWT with minimal required claims:

   - `iss`: Issuer URL (identifies Identity Provider)
   - `exp`: Expiration timestamp
   - `iat`: Issued At timestamp
   - `aud`: Audience (must match PIA's expected audience)
   - Platform-specific:
     - GitHub: `repository`, `repository_owner`, `repository_owner_id` identify
       the publishing repository
     - Jenkins: `iss` identifies the project via URL path

3. **Publish Request**: Publisher sends POST request to PIA:

   - `Authorization` header: Bearer token containing OIDC token (RFC6750)
   - `product_name`: Name of product for which the SBOM is produced. This field
     is required by DependencyTrack to aggregate SBOMs by product within a
     project. We ask the Publisher to provide it, so that we don't have to
     parse the SBOM (see `metadata.component.name`).
   - `product_version`: Version of product for which the SBOM was produced.
     This field is required by DependencyTrack. We ask the Publisher to
     provide it, so that we don't have to parse the SBOM (see
     `metadata.component.version`).
   - `bom`: Base64-encoded CycloneDX JSON SBOM
   - `is_latest`: Whether this SBOM should be marked as the latest version in
     DependencyTrack (optional, default: `true`)

4. **Token Verification and Authentication**: PIA verifies POST data token

   - see 3.1.1. Token Verification and Authentication Flow

5. **DependencyTrack Project Resolution**: PIA looks up the DependencyTrack
   project by matching `name` with `product_name` from the POST data, where the
   DependencyTrack project shares the same `ef_project_id` as the authenticated
   workload. This provides the `dt_parent_uuid` for the DependencyTrack upload.

6. **SBOM Publishing**: PIA sends upload request to DependencyTrack:

   - `Content-Type`: `application/json`
   - `X-Api-Key`: Use internally stored DependencyTrack access token
   - `projectName`: Use `product_name` from POST data
   - `projectVersion`: Use `product_version` from POST data.
   - `parentUUID`: Use `parent_uuid` from matched DependencyTrack project
   - `autoCreate`: `true` (creates new subcategory for new `projectName`)
   - `isLatest`: Use `is_latest` from POST data
   - `bom`: Use `bom` from POST data

#### 3.1.1 Token Verification and Authentication Flow

1. Basic POST Data Validation
   1. Validate basic POST data schema
2. Issuer Validation
   1. Decode token without any verification
   2. Extract issuer
   3. Verify issuer is known
      - GitHub: Full match: `https://token.actions.githubusercontent.com`
      - Jenkins: Parse the issuer as a URL and require an `https` scheme with
        the host exactly equal to `ci.eclipse.org`
3. Token Key Discovery
   1. Fetch OIDC configuration from `{issuer}/.well-known/openid-configuration`
   2. Extract `jwks_uri` from configuration
   3. Fetch public keys from `jwks_uri`
   4. Match key using `kid` claim from token header
4. Token Validation and Signature Verification
   1. Verify generally required claims are present
   2. Verify token issued at time and expiry
   3. Verify audience matches expected value
   4. Verify signature using RSA256
5. Workload Matching
   1. Find workload type by issuer
   2. Find workload by matching verified token claims against workload database:
      - GitHub: match `repo_owner`, `repo_name`, `repo_owner_id`
      - Jenkins: match `issuer`
6. Workload-Specific Claim Verification
   - GitHub: `event_name` must be in the allowlist `{push, workflow_dispatch}`.
     Excludes triggers that can be indirectly driven by non-maintainers
     (`pull_request_target`, `workflow_run`, `issue_comment`, …).
   - Jenkins: no additional checks.

## 4. API Design

### 4.1 Endpoints

#### POST /v1/upload/sbom

Accepts sbom uploads with OIDC authentication.

**Request Headers:**
```
Authorization: Bearer <JWT ID token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "product_name": "string",         // Eclipse product name
  "product_version": "string",      // Eclipse product version
  "bom": "string",                  // CycloneDX JSON SBOM (base64-encoded)
  "is_latest": true                 // Mark as latest version in DependencyTrack (optional, default: true)
}
```

**Response:**
- `200 OK`: SBOM accepted by DependencyTrack. Body provides the URL the
  publisher should poll for processing status:
  ```json
  {
    "polling_url": "https://sbom.eclipse.org/api/v1/bom/token/<token>"
  }
  ```
- `401 Unauthorized`:
  - Invalid Authorization header format
  - Invalid token
  - Expired token
  - Token verification error
  - Issuer not allowed
  - No matching workload found for token claims
  - No matching DependencyTrack project found
- `422 Unprocessable Entity`: Missing Authorization header or invalid JSON
- `502`: DependencyTrack upload request failed
- `*`: Relay DependencyTrack status code and body verbatim (non-2xx)


### 4.2 Settings

PIA requires settings for:

1. **Application**: Loaded from environment variables with `PIA_` prefix:
    - `PIA_DEPENDENCY_TRACK_API_KEY`: DependencyTrack API key (required)
    - `PIA_DATABASE_URL`: PostgreSQL connection string (required)
    - `PIA_DEPENDENCY_TRACK_URL`: DependencyTrack SBOM upload URL
      (default: `https://sbom.eclipse.org/api/v1/bom`)
    - `PIA_EXPECTED_AUDIENCE`: Expected audience for OIDC tokens
      (default: `pia.eclipse.org`)

2. **Database**: PostgreSQL database storing Eclipse Foundation projects,
    workloads, and DependencyTrack projects. See section 4.3 for the data model.


### 4.3 Data Model

#### EclipseFoundationProject
An Eclipse Foundation project. Groups workloads and DependencyTrack projects.
Uses the Eclipse project identifier directly as primary key. Foreign keys
referencing this table use `ON UPDATE CASCADE` to propagate project ID changes.

**Uniqueness:** `PRIMARY KEY(id)`.

| Column | Type | Notes |
|--------|------|-------|
| `id` | String PK | Eclipse project identifier (e.g. `technology.foo`) |

#### Workload (base, polymorphic)
A CI/CD entity that can upload SBOMs. Uses joined-table inheritance with a
`type` discriminator column.

| Column | Type | Notes |
|--------|------|-------|
| `id` | Serial PK | |
| `ef_project_id` | FK → eclipse_foundation_projects.id | |
| `type` | String | Discriminator: `github` or `jenkins` |

#### GitHubWorkload (extends Workload)
Issuer is always `https://token.actions.githubusercontent.com` (constant, not
stored).

**Uniqueness:** `UNIQUE(repo_name, repo_owner, repo_owner_id)`

| Column | Type | Notes |
|--------|------|-------|
| `id` | FK → workloads.id | |
| `repo_name` | String | Repository name (e.g. `my-repo`) |
| `repo_owner` | String | Repository owner (e.g. `eclipse-foo`) |
| `repo_owner_id` | String | GitHub numeric owner ID |

#### JenkinsWorkload (extends Workload)
Each Jenkins workload has a distinct issuer URL.

**Uniqueness:** `UNIQUE(issuer)`

| Column | Type | Notes |
|--------|------|-------|
| `id` | FK → workloads.id | |
| `issuer` | String | OIDC issuer URL (e.g. `https://ci.eclipse.org/<name>/oidc`) |

#### DependencyTrackProject
A DependencyTrack target for SBOM uploads.

**Uniqueness:**
- `UNIQUE(ef_project_id, name)`
- `UNIQUE(name, parent_uuid)`

| Column | Type | Notes |
|--------|------|-------|
| `id` | Serial PK | |
| `ef_project_id` | FK → eclipse_foundation_projects.id | |
| `name` | String | DependencyTrack project name (matched against `product_name` in upload payload) |
| `parent_uuid` | String | DependencyTrack parent project UUID |

#### Authorization Boundary

The Eclipse Foundation project id is the authorization boundary. Any workload
can upload SBOMs for any DependencyTrack project that shares the same Eclipse
Foundation project id.

A workload identity — a GitHub repository (`repo_owner`, `repo_name`,
`repo_owner_id`) or a Jenkins `issuer` — belongs to **exactly one** Eclipse
Foundation project. This is enforced by the workload uniqueness constraints.
Within that scope the target DependencyTrack project is selected by
`product_name`, and `UNIQUE(ef_project_id, name)` makes that selection
unambiguous, while `UNIQUE(name, parent_uuid)` keeps each physical DependencyTrack
project bound to a single EF project.

## 5. Implementation Details

### 5.1 Technology Stack

- **Web Framework**: FastAPI (modern, has built-in model validation and API documentation)
- **Database**: PostgreSQL with SQLAlchemy ORM, `psycopg2`, and Alembic for schema migrations
- **HTTP Client**: `requests` for OIDC discovery and DependencyTrack API calls
- **JWT Library**: `PyJWT` with `cryptography` support
  - Handles token parsing, validation, and signature verification
  - Includes `PyJWKClient` for JWKS key fetching
- **Testing**: `pytest`
- **Linting**: `ruff`
- **Python Project Management**: `uv`

### 5.2 Core Modules

- `main.py`: FastAPI app with:
  - Application settings management
  - Upload SBOM API endpoint implementing full authentication and
    DependencyTrack upload flow (section 3.1, items 4. through 6.)
- `models.py`: Data models:
  - SQLAlchemy declarative `Base`
  - SQLAlchemy ORM models: `EclipseFoundationProject`, `Workload`,
    `GitHubWorkload`, `JenkinsWorkload`, `DependencyTrackProject`
    (see section 4.3)
  - Pydantic request models: `PiaUploadPayload`, `DependencyTrackUploadPayload`
- `oidc.py`: OIDC token validation and signature verification using PyJWT
- `dependencytrack.py`: DependencyTrack API upload client for SBOMs

### 5.3 Error Handling

- **Settings Errors**: Fail fast at startup with clear error

- **Authentication Errors**:
  - 422 for malformed POST data
  - 401 for unknown issuer, token verification errors, no matching workload
    found for verified token claims, or no matching DependencyTrack project
    for the workload's `ef_project_id`

- **DependencyTrack Upload Errors**: 502, if upload fails with an error, or HTTP
    status code from DependencyTrack

### 5.4 Logging and Monitoring

Log important events:
- Settings re-load
- Client connects
- Token verifications
- DependencyTrack uploads
- Errors

Metrics to track:
- Client connect attempts by IP
- Client connect attempts by `product_name` and `product_version`
- Token verification time
- DependencyTrack upload time
- Total API response time

## 6. Security Considerations

### 6.1 Token Validation

- **Issuer and Project**: Only trust allowed issuers and projects
- **Expiration**: Reject expired tokens
- **Signature**: Verify signature before trusting claims
- **Algorithm**: Only accept RS256 (Identity Provider restriction)
- **Key Rotation**: Refresh OIDC configs and JWKs

### 6.2 Attack Vectors

| Attack | Mitigation |
|--------|-----------|
| Token replay | Short-lived tokens (5-10 min), do not re-use token  (future work) |
| Issuer spoofing | HTTPS-only issuer URLs, strict URL validation |
| Token forgery | Cryptographic signature verification |
| Project impersonation | Claim-to-workload validation, project-scoped DependencyTrack project resolution |
| DoS via OIDC discovery | Cache OIDC discovery, rate limit requests (both future work) |
| Parsing vulnerabilities | Use minimal schema for unauthenticated POST data, use well-tested JWT library for token parsing |

### 6.3 Secrets Management

- Store secrets securely in environment variables
- Never log tokens or credentials
- Rotate DependencyTrack credentials regularly

### 6.4 HTTPS Requirements

- All communication must use HTTPS:
  - PIA API endpoint
  - OIDC discovery URLs
  - DependencyTrack API endpoint

## 7. Platform-Specific Details

### 7.1 GitHub Actions

**Identity Provider**:
- Issuer: `https://token.actions.githubusercontent.com`
- OIDC config path: `/.well-known/openid-configuration`

**Verified Claims**:
- `repository_owner_id`: GitHub numeric owner ID
- `repository`: In the form `{repo_owner}/{repo_name}`

**Example Publisher workflow**:
```yaml
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - name: Get ID token
        id: token
        run: |
            ID_TOKEN=$(curl \
                -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
                "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=pia.eclipse.org")

            echo "ID_TOKEN=$ID_TOKEN" >> $GITHUB_OUTPUT

      - name: Publish SBOM
        run: |
          curl -X POST https://pia.eclipse.org/v1/upload/sbom \
            -H "Authorization: Bearer ${{ steps.token.outputs.ID_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d '{"product_name": "...", "product_version": "...", "bom": "..."}'
```

### 7.2 Jenkins

**Identity Providers (one per project)**:
- Issuer: `https://ci.eclipse.org/<PROJECT NAME>/oidc`
- OIDC config path: `/.well-known/openid-configuration`

**Verified Claims**:
- `iss`: The issuer URL identifies the project (e.g.
  `https://ci.eclipse.org/eclipse-baz/oidc` identifies project Eclipse Baz).
  No additional claims required.

**Publisher Setup**:
- Install plugins: `oidc-provider`, `credentials-binding`
- Configure per-project Jenkins instance URL
- Create `id-token` credential
  - Set `GLOBAL` scope, to make tokens available to jobs
  - Set audience, to prevent cross-service token replay

**Example Publisher Credential Setup**:
```yaml
credentials:
  system:
    domainCredentials:
    - credentials:
      - idToken:
          id: id-token
          scope: GLOBAL
          audience: pia.eclipse.org
```

**Example Publisher Pipeline**:
```groovy
pipeline {
    agent any
    environment {
        ID_TOKEN = credentials('id-token')
    }
    stages {
        stage('Publish') {
            steps {
                sh '''
                  curl -X POST https://pia.eclipse.org/v1/upload/sbom \
                    -H "Authorization: Bearer ${ID_TOKEN}" \
                    -H "Content-Type: application/json" \
                    -d '{"product_name": "...", "product_version": "...", "bom": "..."}'
                '''
            }
        }
    }
}
```

## 8. Deployment

### 8.1 Environment

- Python 3.13.2+
- Production ASGI server (e.g., uvicorn)
- Reverse proxy for TLS termination and rate limiting
- Container deployment

### 8.2 Settings

Settings via:
1. PostgreSQL database for Eclipse Foundation projects, workloads, and DependencyTrack projects (see section 4.3)
2. Environment variables (with `PIA_` prefix) for application settings

Required environment variables:
```bash
PIA_DEPENDENCY_TRACK_API_KEY=<your-api-key>
PIA_DATABASE_URL=postgresql://user:pass@host:5432/pia
PIA_DEPENDENCY_TRACK_URL=https://sbom.eclipse.org/api/v1/bom  # optional, has default
PIA_EXPECTED_AUDIENCE=pia.eclipse.org  # optional, has default
```

### 8.3 Scalability

- Stateless: Can run multiple instances behind load balancer
- Rate limiting per project/IP at reverse proxy level, if needed
- Async processing, if needed

## 9. Testing Strategy

### 9.1. Unit Tests

- Settings loading and validation (pydantic-settings)
- Model validation (pydantic models)
- Token verification and authentication logic with test tokens
- Error handling paths

### 9.2. Integration tests
- FastAPI endpoints using httpx async test client
- DependencyTrack upload with mock server

## 10. Future Work

- Add caching for oidc config and jwks
- Add monitoring
- Make upload API async, if sync takes too long
- Protect against replayed tokens (PyPI uses "jti" claim to track used tokens)
- Consider product-level authentication

## 11. References

- [Trusted Publishing (PyPI)](https://docs.pypi.org/trusted-publishers/)
- [GitHub OIDC Documentation](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [Jenkins OIDC Provider Plugin](https://plugins.jenkins.io/oidc-provider/)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
- [RFC6750 - OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [End-to-end Proof of Concept](https://gitlab.eclipse.org/lukpueh/oidc-upload-demo)
- [Concept Document (restricted access)](https://docs.google.com/document/d/1DuvC7vRsbJQpY9q4selLuAuAO4AUXiyEmHrK-xQ6GW0/edit?tab=t.0#heading=h.k5o4i1fbhpd2)


## Appendix A: Token Examples

### GitHub Actions Token

```json
{
  "jti": "...",
  "sub": "repo:octo-org/octo-repo:ref:refs/heads/main",
  "aud": "pia.eclipse.org",
  "ref": "refs/heads/main",
  "sha": "...",
  "repository": "octo-org/octo-repo",
  "repository_owner": "octo-org",
  "run_id": "...",
  "run_number": "...",
  "run_attempt": "...",
  "actor": "octocat",
  "workflow": "CI",
  "head_ref": "",
  "base_ref": "",
  "event_name": "push",
  "ref_type": "branch",
  "job_workflow_ref": "octo-org/octo-repo/.github/workflows/ci.yml@refs/heads/main",
  "iss": "https://token.actions.githubusercontent.com",
  "nbf": 1632492000,
  "exp": 1632492900,
  "iat": 1632492000
}
```

### Jenkins Token

```json
{
    "aud": "pia.eclipse.org",
    "build_number": 2,
    "exp": 1765461015,
    "iat": 1765457415,
    "iss": "https://ci.eclipse.org/my-project/oidc",
    "sub": "https://ci.eclipse.org/my-project/job/oidc-upload-demo/"
}
```
