FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev

COPY src/censys_collections /opt/opencti-connector-censys-collections/src/censys_collections
COPY pyproject.toml /opt/opencti-connector-censys-collections/pyproject.toml
WORKDIR /opt/opencti-connector-censys-collections

# git is required to resolve the connectors-sdk VCS dependency declared in pyproject.toml
RUN pip3 install --no-cache-dir . && \
    apk del git build-base

CMD ["censys-collections-connector"]
