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

# The console script runs from /usr/local/bin, so pycti finds the version stamp
# only in the working directory, not in the installed package. The `[n]` makes
# this copy optional: the stamp is written by the CI and is absent from local
# builds, and a plain COPY would fail there. Do not "fix" it into a literal filename.
COPY .connector_version.jso[n] ./

CMD ["zetalytics-dns-connector"]
