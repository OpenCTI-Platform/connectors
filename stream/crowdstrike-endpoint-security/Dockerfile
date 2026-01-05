FROM python:3.12-alpine
ENV CONNECTOR_TYPE=STREAM

# Copy the worker
COPY src /opt/opencti-connector-crowdstrike-endpoint-security

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

WORKDIR /opt/opencti-connector-crowdstrike-endpoint-security
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]
