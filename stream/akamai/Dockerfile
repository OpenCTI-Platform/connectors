# Use lightweight Python Alpine image
FROM python:3.12-alpine

# Connector type used by OpenCTI connector manager
ENV CONNECTOR_TYPE=STREAM

# Prevent Python from creating .pyc files
ENV PYTHONDONTWRITEBYTECODE=1

# Disable stdout buffering (important for logs in Docker)
ENV PYTHONUNBUFFERED=1

# Set working directory inside container
WORKDIR /opt/opencti-connector-akamai

# Install system dependencies required for cryptography and EdgeGrid

RUN apk add --no-cache \
    build-base \
    libffi-dev \
    openssl-dev \
    ca-certificates

# Copy Python dependencies first (better Docker layer caching)
COPY src/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy full source code (including config.yml.sample)
COPY src/ .

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Container entrypoint
ENTRYPOINT ["/entrypoint.sh"]