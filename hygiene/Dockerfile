FROM python:3.9-alpine

# Copy the worker
COPY src /opt/opencti-connector-hygiene

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev rust cargo openssl-dev && \
    cd /opt/opencti-connector-hygiene && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base rust cargo openssl-dev

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
