FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV CONNECTOR_ENRICHMENT_RESOLUTION=PT1M

# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add build-base libmagic libffi-dev

COPY connector /opt/opencti-connector-google-ti-feeds/connector
COPY pyproject.toml /opt/opencti-connector-google-ti-feeds/pyproject.toml
WORKDIR /opt/opencti-connector-google-ti-feeds

RUN pip3 install --no-cache-dir . && \
    apk del build-base

CMD ["GoogleTIFeeds"]
