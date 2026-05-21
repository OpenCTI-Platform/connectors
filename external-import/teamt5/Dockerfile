# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12.5
FROM python:${PYTHON_VERSION}-alpine AS base

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

# Install dependencies
# Avoid an image layer for those files.
RUN --mount=type=bind,source=src/requirements.txt,target=requirements.txt \
    apk add --no-cache --virtual .build-deps build-base libffi-dev git && \
    python -m pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Copy the connector
COPY src .

# Execute the connector
CMD [ "python", "main.py" ]

