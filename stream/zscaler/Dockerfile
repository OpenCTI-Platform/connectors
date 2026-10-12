FROM python:3.12-alpine

ENV CONNECTOR_TYPE=STREAM

# Copy the worker
COPY src /opt/opencti-connector-zscaler
WORKDIR /opt/opencti-connector-zscaler

# Install Python modules and dependencies
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-zscaler && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["python3", "main.py"]
