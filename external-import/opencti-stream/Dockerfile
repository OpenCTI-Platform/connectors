FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-opencti-stream
WORKDIR /opt/opencti-connector-opencti-stream

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["python3", "main.py"]
