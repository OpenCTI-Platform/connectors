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

# Install the connector as a proper package. Its packages live under src/
# (src/ layout: connector/, vulncheck_client/), discovered via
# [tool.setuptools.packages.find] where=["src"]. Copy the source + project
# metadata in, install into site-packages, then drop the build inputs so the
# source tree doesn't bloat the final image (matches the src/-layout peers).
COPY src ./src
COPY pyproject.toml ./pyproject.toml
RUN python -m pip install --no-cache-dir . && \
  apk del git build-base && \
  rm -rf ./src ./pyproject.toml ./build

# main.py is a top-level entry script (not part of an installed package), so
# copy it in explicitly; connector/ and vulncheck_client/ resolve from
# site-packages.
COPY src/main.py .

# Execute the connector
CMD [ "python", "main.py" ]
