FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-beaconbeagle

# Install Python modules and runtime tools in a single layer.
# ``whois`` is required at runtime when ``BEACONBEAGLE_SEARCH_BGPAS=true``
# (the connector shells out to ``whois -h bgp.tools``); keep it in the
# final image while discarding the build-only tooling once the wheels
# are compiled. We deliberately avoid ``apk update && apk upgrade`` so
# rebuilds against the same ``python:3.12-alpine`` base produce
# reproducible images instead of silently pulling in whichever Alpine
# package versions happen to be current at build time.
RUN apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev whois && \
    cd /opt/opencti-connector-beaconbeagle && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base libxslt-dev libxml2-dev

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
