FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy ONLY the requirements file first so the ``pip install`` layer
# can be cached across rebuilds whenever the connector source changes
# but dependencies do not. Copying the full ``src/`` tree before
# ``pip install`` (as the earlier shape did) invalidated the
# dependency-install layer on every source edit — slow on CI and
# unnecessary. Matches the established
# ``internal-enrichment/joe-sandbox/Dockerfile`` pattern referenced in
# the ``apk`` rationale below.
COPY src/requirements.txt /opt/opencti-connector-assemblyline/requirements.txt

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

# Copy the rest of the source tree AFTER ``pip install`` so the
# preceding dependency-install layer stays cache-friendly across
# source-only rebuilds.
COPY src /opt/opencti-connector-assemblyline

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
