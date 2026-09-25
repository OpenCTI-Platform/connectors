FROM python:3.12-alpine

ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev

COPY src/zetalytics_dns /opt/opencti-connector-zetalytics-dns/src/zetalytics_dns
COPY pyproject.toml /opt/opencti-connector-zetalytics-dns/pyproject.toml
WORKDIR /opt/opencti-connector-zetalytics-dns

# git is required to resolve the connectors-sdk VCS dependency declared in pyproject.toml
RUN pip3 install --no-cache-dir . && \
    apk del git build-base

CMD ["zetalytics-dns-connector"]
