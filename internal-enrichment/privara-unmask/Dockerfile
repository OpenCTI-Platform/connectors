ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-alpine AS base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/opencti-connector-privara-unmask
WORKDIR /opt/opencti-connector-privara-unmask

# Install Python dependencies and remove build dependencies
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libffi-dev libxml2-dev libxslt-dev

# Run as an unprivileged user (the connector needs no write access to its folder)
RUN adduser -D -H -s /sbin/nologin connector
USER connector

# Expose and entrypoint
ENTRYPOINT ["python", "main.py"]
