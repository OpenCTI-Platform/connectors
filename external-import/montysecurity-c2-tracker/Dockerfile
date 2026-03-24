FROM python:3.12-alpine AS builder

# Install Python modules
# hadolint ignore=DL3003
WORKDIR /opt/opencti-connector-montysecurity-c2-tracker

# Install build dependencies and libraries required by Python modules
RUN apk --no-cache add \
    git \
    build-base \
    libmagic \
    libxml2-dev \
    libxslt-dev \
    libffi-dev

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ENV UV_LINK_MODE=copy
# Create a virtual environment and install dependencies
RUN uv venv
RUN --mount=type=bind,source=src/requirements.txt,target=/tmp/requirements.txt \
    --mount=type=cache,target=/root/.cache/uv \
    uv pip install -r /tmp/requirements.txt


FROM python:3.12-alpine AS runner
WORKDIR /opt/opencti-connector-montysecurity-c2-tracker

# Install runtime dependencies
RUN apk --no-cache add \
    libmagic \
    libxml2 \
    libxslt \
    libffi

# Create an unprivileged runtime user used by COPY --chown and final process.
RUN addgroup -S app && adduser -S -G app app
# Copy the connector
COPY --chown=app:app src .
# Copy the virtual environment from the builder stage
COPY --from=builder --chown=app:app /opt/opencti-connector-montysecurity-c2-tracker/.venv ./.venv
# Switch to the unprivileged user
USER app

# Set PATH to use the virtual environment
ENV PATH="/opt/opencti-connector-montysecurity-c2-tracker/.venv/bin:$PATH"

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]
