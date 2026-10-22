FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-google-safebrowsing
WORKDIR /opt/opencti-connector-google-safebrowsing

# Install Python modules and remove build dependencies
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
ENTRYPOINT ["python3", "main.py"]
