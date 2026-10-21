FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-beaconbeagle

# Install Python modules and runtime tools in a single layer.
# ``whois`` is required at runtime when ``BEACONBEAGLE_SEARCH_BGPAS=true``
# (the connector shells out to ``whois -h bgp.tools``); keep it in the
# final image while discarding the build-only tooling once the wheels
# are compiled.
WORKDIR /opt/opencti-connector-beaconbeagle
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev whois && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base libxslt-dev libxml2-dev

# Run the connector directly as PID 1 so it receives SIGTERM/SIGINT and Docker
# can perform a graceful shutdown (no shell wrapper to forward signals through).
ENTRYPOINT ["python3", "BeaconBeagle.py"]
