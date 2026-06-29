#!/bin/sh
# Container start script used as the image CMD.
#
# Applies any pending database migrations, then starts the app. Chaining the
# migration with the app start is acceptable here because "alembic upgrade head"
# is idempotent: if the schema is already current it is a no-op, and Alembic
# takes a lock so concurrent replicas don't migrate at the same time.
#
# `exec` replaces this shell with uvicorn so it runs as PID 1 and receives
# signals (SIGTERM on shutdown) directly. Any extra arguments passed to the
# container are forwarded to uvicorn.
set -eu

alembic upgrade head

exec uvicorn pia.main:app --host 0.0.0.0 --port 8000 "$@"
