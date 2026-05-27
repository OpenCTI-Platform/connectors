FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-beaconbeagle

# Install Python modules and runtime tools. ``whois`` is required at
# runtime when ``BEACONBEAGLE_SEARCH_BGPAS=true`` (the connector shells
# out to ``whois -h bgp.tools``); keep it in the final image while
# discarding the build-only tooling once the wheels are compiled.
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev whois && \
    cd /opt/opencti-connector-beaconbeagle && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base libxslt-dev libxml2-dev && \
    rm -rf /var/cache/apk/*

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]