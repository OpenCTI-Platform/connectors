# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12.7
FROM python:${PYTHON_VERSION}-alpine as base

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
RUN apk update && apk upgrade && \
  apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.
RUN --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
  python -m pip install --no-cache-dir .

# Remove dependencies for pip installing after completed
RUN apk del git build-base

# Copy the connector
COPY src .

# Execute the connector
CMD [ "python", "main.py" ]
