FROM python:3.8-alpine

# Copy the worker
COPY src /opt/opencti-connector-export-file-stix

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-export-file-stix && \
    pip3 install --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@4.1.0 && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh 
ENTRYPOINT ["/entrypoint.sh"]
