FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY spycloud_connector /opt/spycloud_connector
COPY pyproject.toml /opt/pyproject.toml
COPY main.py /opt/main.py
# This connector has no src/ to carry a version stamp, so it is copied straight
# to the entry script's directory. The `[n]` makes the copy optional: the stamp
# is written by the CI and is absent from local builds, and a plain COPY would
# fail there. Do not "fix" it into a literal filename.
COPY .connector_version.jso[n] /opt/

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt && \
    pip3 install --no-cache-dir . && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
