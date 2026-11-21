FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libffi-dev

COPY src/censys_collections /opt/opencti-connector-censys-collections/src/censys_collections
COPY pyproject.toml /opt/opencti-connector-censys-collections/pyproject.toml
WORKDIR /opt/opencti-connector-censys-collections

# git is required to resolve the connectors-sdk VCS dependency declared in pyproject.toml
RUN pip3 install --no-cache-dir . && \
    apk del git build-base libffi-dev

# The console script runs from /usr/local/bin, so pycti finds the version stamp
# only in the working directory, not in the installed package. The `[n]` makes
# this copy optional: the stamp is written by the CI and is absent from local
# builds, and a plain COPY would fail there. Do not "fix" it into a literal filename.
COPY .connector_version.jso[n] ./

CMD ["censys-collections-connector"]
