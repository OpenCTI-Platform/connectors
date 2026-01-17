# OpenCTI DataDog Connector Dockerfile

FROM python:3.12-alpine

# Build argument for pycti version (injected from pycti-version.env)
ARG PYCTI_VERSION=6.8.10

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV CONNECTOR_DIR=/opt/opencti-connector-datadog-import
# Prevents pip conflicts on modern Alpine images
ENV PIP_BREAK_SYSTEM_PACKAGES=1

COPY src ${CONNECTOR_DIR}

# Install system dependencies and Python modules
RUN apk update && apk upgrade

# Install build-time and Python dependencies
RUN apk --no-cache add \
        # System dependencies for building
        git \
        build-base \
        libmagic \
        # Dev headers for compiling python packages (like lxml)
        libxslt-dev \
        libxml2-dev \
        # CRITICAL: Python dev headers and libffi (for cryptography)
        python3-dev \
        libffi-dev

RUN pip install --upgrade pip

# Install pycti from centralized version, then connector-specific deps
RUN pip install --no-cache-dir pycti==${PYCTI_VERSION} \
    && cd ${CONNECTOR_DIR} \
    && pip install --no-cache-dir -r requirements.txt

# Clean up build dependencies to keep image small
RUN apk del git build-base libxslt-dev libxml2-dev python3-dev libffi-dev \
    && rm -rf /var/cache/apk/*

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
