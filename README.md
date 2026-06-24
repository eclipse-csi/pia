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
migrations. Migration scripts live in `alembic/versions/` and are automatically
applied as part of the deployment.

#### Creating Migration Scripts

To auto-generate a migration script, when adding, removing or changing PIA ORM
models (see `pia/models.py`), run below command and add the resulting script to
version control.
```shell
docker compose run --rm --entrypoint='alembic revision --autogenerate --message "MESSAGE"' pia
```
