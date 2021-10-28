FROM python:3.9-alpine

# Copy the connector
COPY src /opt/opencti-connector-sethsites

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-sethsites && \
    pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
