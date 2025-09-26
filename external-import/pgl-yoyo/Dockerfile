FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY --chmod=0755 entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]