FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy requirements
WORKDIR /opt/opencti-connector-greynoise-vuln
COPY src/requirements.txt .

# Install Python modules
# hadolint ignore=DL3003

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy source code
COPY src .

# Expose
ENTRYPOINT ["python3", "main.py"]
