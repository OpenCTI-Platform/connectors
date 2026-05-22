ARG PYTHON_VERSION=3.12.5
FROM python:${PYTHON_VERSION}-alpine

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# ``libmagic`` is a runtime dep (used at request time, not build time)
# and stays in the final image. ``git`` is only needed by ``pip`` to
# resolve the ``git+https://…@master#subdirectory=connectors-sdk``
# requirement, so it joins ``build-base`` / ``libffi-dev`` under
# ``--virtual .build-deps`` and gets dropped together with them after
# ``pip install`` — keeping the runtime layer free of the git binary
# (smaller image, smaller attack surface, no accidental network shell
# from inside the container).
RUN apk add --no-cache libmagic

# Copy ONLY ``requirements.txt`` first so the ``pip install`` layer is
# cached across rebuilds whenever the connector source changes but the
# dependency set does not. Match the standard pattern used by every
# other connector in this monorepo (e.g.
# ``internal-enrichment/joe-sandbox/Dockerfile``); the earlier
# ``RUN --mount=type=bind,...`` shape only worked when the caller had
# BuildKit enabled, which is not guaranteed across CI / local Docker
# Compose setups still using the legacy builder. Reverting to plain
# ``COPY`` keeps the build green on every Docker version we ship.
COPY src/requirements.txt requirements.txt

# Install dependencies. ``--virtual .build-deps`` groups the build-only
# toolchain so the entire bundle (``git`` included — see the comment
# above) can be dropped in the same ``RUN`` once ``pip install`` is
# done.
# hadolint ignore=DL3003
RUN apk add --no-cache --virtual .build-deps build-base libffi-dev git && \
    python -m pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Copy the rest of the source tree AFTER ``pip install`` so the
# preceding dependency-install layer stays cache-friendly across
# source-only rebuilds.
COPY src .

# Execute the connector
CMD [ "python", "main.py" ]
