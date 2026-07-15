FROM python:3.12-slim

# Metadata
LABEL maintainer="IPGeolocation.io OpenCTI Connector"
LABEL org.opencontainers.image.title="OpenCTI IPGeolocation.io Enrichment Connector"
LABEL org.opencontainers.image.description="Internal enrichment connector for IPGeolocation.io v3 APIs"

# Security: run as non-root
RUN useradd -ms /bin/bash connector

# Install system dependency required by pycti (python-magic)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies
WORKDIR /opt/opencti-connector
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# Copy source
COPY src/ ./src/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Switch to non-root
USER connector

ENTRYPOINT ["/opt/opencti-connector/entrypoint.sh"]
