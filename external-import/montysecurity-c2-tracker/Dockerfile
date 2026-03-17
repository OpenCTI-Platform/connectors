FROM python:3.12-alpine AS builder

# Install Python modules
# hadolint ignore=DL3003
WORKDIR /opt/opencti-connector-montysecurity-c2-tracker

RUN apk --no-cache add \
    git \
    build-base \
    libmagic \
    libxml2-dev \
    libxslt-dev \
    libffi-dev

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ENV UV_LINK_MODE=copy
RUN uv venv
RUN --mount=type=bind,source=src/requirements.txt,target=/tmp/requirements.txt \
    --mount=type=cache,target=/root/.cache/uv \
    uv pip install -r /tmp/requirements.txt


FROM python:3.12-alpine AS runner
WORKDIR /opt/opencti-connector-montysecurity-c2-tracker

RUN apk --no-cache add \
    libmagic \
    libxml2 \
    libxslt \
    libffi

# Copy the connector
COPY  src .
COPY --from=builder --chown=app:app /opt/opencti-connector-montysecurity-c2-tracker/.venv ./.venv

# Expose and entrypoint
ENTRYPOINT ["/opt/opencti-connector-montysecurity-c2-tracker/.venv/bin/python3", "main.py"]
