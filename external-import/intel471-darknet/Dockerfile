FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector source.
COPY src /opt/opencti-connector-intel471-darknet

# Install the Python modules required at runtime. Build dependencies are
# installed in the same RUN layer and removed before the layer is committed
# so they do not bloat the runtime image / increase the attack surface.
# hadolint ignore=DL3018,DL3003
RUN apk --no-cache add \
        build-base \
        git \
        libffi-dev \
        libmagic \
        libxml2-dev \
        libxslt-dev && \
    cd /opt/opencti-connector-intel471-darknet && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del build-base git

# Expose and entrypoint.
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
