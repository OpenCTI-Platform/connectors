FROM python:3.12-alpine

# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev
# Copy the connector
COPY src /opt/opencti-connector-mitre-atlas
WORKDIR /opt/opencti-connector-mitre-atlas

# Install Python modules
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
ENTRYPOINT ["python", "main.py"]
