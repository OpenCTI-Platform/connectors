FROM python:3.12-alpine

# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/opencti-connector-microsoft-sentinel-incidents
WORKDIR /opt/opencti-connector-microsoft-sentinel-incidents

# Install Python modules
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
ENTRYPOINT ["python", "main.py"]
