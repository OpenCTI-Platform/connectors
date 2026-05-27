FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the worker
COPY src /opt/opencti-connector-hybrid-analysis-sandbox

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-hybrid-analysis-sandbox && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

WORKDIR /opt/opencti-connector-hybrid-analysis-sandbox
ENTRYPOINT ["python", "main.py"]
