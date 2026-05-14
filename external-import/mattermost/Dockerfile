FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-mattermost

# Install Python modules. ``libmagic`` is the only runtime native library
# we keep around (used by ``python-magic`` pulled in via ``pycti``);
# ``git`` and ``build-base`` are install-time only and are removed after
# ``pip install`` to keep the image slim. None of the pinned dependencies
# (``pycti``, ``mattermostdriver``, ``stix2``) require ``libxml2`` /
# ``libxslt``, so we do not pull those in either.
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-mattermost && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
