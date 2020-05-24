FROM python:3.8-alpine

WORKDIR  /opt/opencti-connector-cybercrimetracker

COPY src/requirements.txt  ./
# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add build-base libmagic libxml2 libxml2-dev libxslt libxslt-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base

# Copy the connector
COPY src entrypoint.sh ./

ENTRYPOINT ["/bin/sh", "-c", "/opt/opencti-connector-cybercrimetracker/entrypoint.sh"]
