FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Set working directory inside container
WORKDIR /opt/opencti-connector-whoisfreaks

# Install system runtime dependencies needed by pycti and stix2
# Install system runtime/build dependencies needed by pycti and stix2
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev

# Install Python package dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy source code and entrypoint
COPY src ./src
COPY entrypoint.sh .

# Ensure entrypoint is executable
RUN chmod +x entrypoint.sh

# Run startup script
ENTRYPOINT ["/entrypoint.sh"]