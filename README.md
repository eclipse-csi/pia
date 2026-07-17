# Project Identity Authority (PIA)
Authenticates Eclipse Foundation projects using OpenID Connect (OIDC).

See [Design Document](docs/DESIGN.md) for details.

## Contributing

### Development Setup

PIA uses [uv](https://docs.astral.sh/uv/) for Python project management.

1. **Clone and changew into repository:**
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
