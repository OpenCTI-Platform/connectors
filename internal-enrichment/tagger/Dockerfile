FROM python:3.11-alpine

# Copy the worker
COPY src /opt/opencti-connector-tagger
WORKDIR /opt/opencti-connector-tagger

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-tagger && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["python", "connector.py"]
