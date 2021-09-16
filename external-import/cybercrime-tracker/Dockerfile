FROM python:3.9-alpine

WORKDIR  /opt/opencti-connector-cybercrime-tracker

COPY src/requirements.txt  ./
# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add build-base git libmagic libxml2 libxml2-dev libxslt libxslt-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base git

# Copy the connector
COPY src entrypoint.sh ./
RUN chmod +x ./entrypoint.sh
ENTRYPOINT ["/bin/sh", "-c", "/opt/opencti-connector-cybercrime-tracker/entrypoint.sh"]
