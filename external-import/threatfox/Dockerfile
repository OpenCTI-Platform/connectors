FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev

COPY src /opt/opencti-connector-threatfox/src
COPY pyproject.toml /opt/opencti-connector-threatfox/pyproject.toml
WORKDIR /opt/opencti-connector-threatfox

# git is required to resolve the connectors-sdk VCS dependency declared in pyproject.toml
RUN pip3 install --no-cache-dir . && \
    apk del git build-base

CMD ["threatfox-connector"]
