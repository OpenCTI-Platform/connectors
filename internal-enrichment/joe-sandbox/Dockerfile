FROM python:3.10-alpine

# Copy the worker
COPY src/requirements.txt /opt/opencti-connector-joe-sandbox/requirements.txt

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-joe-sandbox && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY src /opt/opencti-connector-joe-sandbox

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
