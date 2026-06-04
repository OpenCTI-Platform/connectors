FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the worker
COPY src /opt/opencti-connector-greynoise-vuln

# Install Python modules
# hadolint ignore=DL3003
WORKDIR /opt/opencti-connector-greynoise-vuln
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose
ENTRYPOINT ["python3", "main.py"]
