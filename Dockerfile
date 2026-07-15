# This is a single image for all three PIA entrypoints: the web app (the default
# CMD, `uvicorn`), the database migration job (`alembic upgrade head`), and the
# management CLI (`pia sync`). They share the same code, ORM models, and
# migration scripts and must stay version-locked with each other, so bundling
# them avoids the drift and release complexity of keeping separate images in
# sync; the callers simply override the command. The extra footprint is
# negligible — the CLI adds only `click` (already pulled in by uvicorn) and
# `pyyaml` — so splitting it out would add build/publish overhead for no
# meaningful size or attack-surface gain.

# Build stage
FROM python:3.14.2-slim@sha256:2751cbe93751f0147bc1584be957c6dd4c5f977c3d4e0396b56456a9fd4ed137 AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1

# note: we need README.md because it is referenced in pyproject.toml
COPY alembic.ini pyproject.toml uv.lock README.md ./
COPY alembic/ ./alembic/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY pia/ ./pia/

# Runtime stage
FROM python:3.14.2-slim@sha256:2751cbe93751f0147bc1584be957c6dd4c5f977c3d4e0396b56456a9fd4ed137 AS runtime

RUN groupadd -r app && useradd -r -g app app

WORKDIR /app

COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --from=builder --chown=app:app /app/pia /app/pia
COPY --from=builder --chown=app:app /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=app:app /app/alembic /app/alembic
COPY --from=builder --chown=app:app /app/alembic.ini /app/alembic.ini

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT="/app/.venv"

USER app

EXPOSE 8000

# Start the app. Database migrations are NOT run here; they are applied as a
# separate step before rollout (a Helm pre-upgrade hook job in production that
# runs `alembic upgrade head` using this same image). The alembic CLI is
# available in the image for that override.
CMD ["uvicorn", "pia.main:app", "--host", "0.0.0.0", "--port", "8000"]
