# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-alpine AS base

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev ca-certificates

# Install the connector as a proper package (src/ layout: connector/,
# whoisfreaks_client/). Then drop build inputs so the source tree does not
# bloat the final image.
COPY src ./src
COPY pyproject.toml ./pyproject.toml

RUN git config --global http.postBuffer 524288000 && \
    python -m pip install --no-cache-dir --upgrade pip && \
    python -m pip install --no-cache-dir . && \
    apk del git build-base && \
    rm -rf ./src ./pyproject.toml ./build

# main.py is a top-level entry script (not part of an installed package).
COPY src/main.py .
ENTRYPOINT ["python", "main.py"]
