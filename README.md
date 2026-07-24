# Project Identity Authority (PIA)
Authenticates Eclipse Foundation projects using OpenID Connect (OIDC) for the
purpose of uploading SBOMs to the Eclipse Foundation DependencyTrack instance.

> [!IMPORTANT]
> **Authorization is scoped to the Eclipse Foundation project — not to an
> individual workload or DependencyTrack project.** Workloads (GitHub repos or
> Jenkins instances) and DependencyTrack projects are both registered *under* an EF
> project. Any workload registered for an EF project may publish an SBOM to **any**
> DependencyTrack project registered for that **same** EF project; there is no
> per-workload → per-DependencyTrack-project binding. Which DependencyTrack project
> a given upload lands in is decided at upload time by the **`product_name`** field
> in the request payload: PIA resolves it to the DependencyTrack project. In
> other words, the workload authenticates and establishes the EF-project scope, and
> `product_name` selects the target within that scope.

See [Design Document](docs/DESIGN.md) for details.

## Contributing

### Development Setup

PIA uses [uv](https://docs.astral.sh/uv/) for Python project management.

1. **Clone and change into repository:**
   ```bash
   git clone https://github.com/eclipse-csi/pia.git && cd pia
   ```

2. **Install dependencies:**
   ```bash
   uv sync --all-extras
   ```

### Running Tests

Run the full test suite with pytest:

```bash
uv run pytest                             # all tests
uv run pytest -v                          # verbose output
uv run pytest tests/test_main.py          # specific test
uv run pytest --cov=pia                   # with coverage
```

### Code Quality

Lint and check format

```bash
uv run ruff check && uv run ruff format --check
```

Auto-fix linting issues and auto-format

```bash
uv run ruff check --fix && uv run ruff format
```

### Database Migration

PIA uses [`alembic`](https://alembic.sqlalchemy.org/en/latest/) for database
migrations. Migration scripts live in `alembic/versions/`.

Migrations are applied as a dedicated step before the app rolls out, by running
`alembic upgrade head` with the application image — in production via a Helm
`pre-install`/`pre-upgrade` hook job (see the [helm
chart](https://github.com/eclipse-csi/helm-charts/tree/main/charts/pia)). The
app itself does not run migrations on startup, so its runtime database user only
needs read access. In local development, the `docker-compose` setup applies
migrations automatically before starting the app for convenience.

#### Creating Migration Scripts

To auto-generate a migration script, when adding, removing or changing PIA ORM
models (see `pia/models.py`), run below command and add the resulting script to
version control.
```shell
docker compose run --rm pia alembic revision --autogenerate --message "MESSAGE"
```

### Managing Authorizations

Project authorizations (workloads and DependencyTrack targets) live in the
database and are managed declaratively: reconcile the whole set from a curated
file with `pia sync`.

Use `pia create-dt-projects` to ensure existence of DependencyTrack targets
prior to syncing.

See [CLI section of the design doc](docs/DESIGN.md#55-cli-tool) or run with
`--help` for more info.

#### Local Testing

The `docker compose` stack includes a local DependencyTrack API server, so you
can exercise `pia sync` end to end.

1. **Start the stack.** This brings up Postgres, DependencyTrack, and the app
   (which applies migrations on startup):
   ```shell
   docker compose up -d
   ```

2. **Provision a DependencyTrack token.** DependencyTrack takes 1-2 minutes to
   become ready on first start; this command waits for it and creates an API
   token:
   ```shell
   uv run python scripts/dt_bootstrap.py
   ```
   The DependencyTrack UI/API is at http://localhost:8080 (admin login is
   printed by the command).

3. **Run a sync** against the local database and DependencyTrack using the
   command printed by `scripts/dt_bootstrap.py`.

   Drop `--dry-run` to apply, then re-run to see an empty (idempotent) plan.
   Edit `projects.local.yaml` and re-run to see updates and deletions in the plan.
