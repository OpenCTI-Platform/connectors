FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/connector/src
WORKDIR /opt/connector/src

RUN pip3 install --no-cache-dir -r /opt/connector/src/requirements.txt
RUN rm -rf /var/cache/apk/*

RUN adduser -D -u 10001 -G root connector \
    && chown -R :root /opt/connector \
    && chmod -R g+rwX /opt/connector

HEALTHCHECK --interval=5m --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -f "python3 main.py" > /dev/null || exit 1

USER 10001
ENTRYPOINT ["python3", "main.py"]
