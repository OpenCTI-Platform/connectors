FROM python:3.12-alpine

# Install dependencies
RUN apk --no-cache add git build-base libmagic libffi-dev

# Copy the connector
COPY src /opt/opencti-connector-valhalla
WORKDIR /opt/opencti-connector-valhalla

# Install Python modules
# hadolint ignore=DL3003
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]
