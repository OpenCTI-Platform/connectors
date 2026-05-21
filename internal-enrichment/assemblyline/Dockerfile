FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-assemblyline

# Install Python modules.
# ``assemblyline-client==4.9.9`` pulls ``pycryptodome``, ``python-baseconv``,
# ``python-socketio``, ``requests``, ``socketio-client`` — none of which
# need ``libxml2`` / ``libxslt`` (no ``lxml`` in the dependency tree), so
# the matching ``-dev`` headers used to bloat the final image and widen
# the vulnerability surface for nothing. Match the lean
# ``internal-enrichment/joe-sandbox`` pattern: ``libmagic`` +
# ``libffi-dev`` for the runtime, ``git`` + ``build-base`` only for
# ``pip install`` (removed afterwards).
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-assemblyline && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
