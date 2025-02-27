FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
ARG SRC_DIR=/opt/opencti-connector-bambenek

# Install Python modules
# hadolint ignore=DL3003

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd $SRC_DIR && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY src $SRC_DIR

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
