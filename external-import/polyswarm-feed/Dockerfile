ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-alpine AS base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/opencti-connector-polyswarm-feed
WORKDIR /opt/opencti-connector-polyswarm-feed

# Install Python dependencies and remove build dependencies
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Run as an unprivileged user. The connector writes nothing to disk.
RUN adduser -D -H -u 10001 connector
USER connector

# Expose and entrypoint
ENTRYPOINT ["python", "main.py"]
