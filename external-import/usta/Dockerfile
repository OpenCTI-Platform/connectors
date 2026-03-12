FROM python:3.12-alpine

# Install build dependencies for native packages
RUN apk add --no-cache \
    git \
    build-base \
    libffi-dev \
    openssl-dev

# Create connector directory
COPY src /opt/opencti-connector-usta-prodaft

# Install Python dependencies
RUN cd /opt/opencti-connector-usta-prodaft && \
    pip install --no-cache-dir -r requirements.txt

# Copy entrypoint
COPY entrypoint.sh /

# Make entrypoint executable
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
