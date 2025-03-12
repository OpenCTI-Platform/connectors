FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-cvelistv5

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-cvelistv5 && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base

# Need this because of GitPython (Issue 1979)
RUN ln -sv $(which uname) /usr/bin/uname

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
