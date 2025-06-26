FROM python:3.11-alpine
ENV CONNECTOR_TYPE=STREAM

# Copy the worker
COPY src /opt/opencti-connector-splunk

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-splunk && \
    pip3 install "setuptools~=78.1.0" && pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base
# explicit setuptools version due to https://github.com/OpenCTI-Platform/connectors/issues/3742

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
