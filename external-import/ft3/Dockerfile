FROM python:3.11-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the worker
COPY src /opt/opencti-connector-ft3/src

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-ft3/src && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
WORKDIR /opt/opencti-connector-ft3
CMD ["python3", "-m", "src"]
