FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /opt/opencti-connector-rst-threat-feed

COPY src /opt/opencti-connector-rst-threat-feed/src

RUN apk --no-cache add --virtual .build-deps git build-base && \
    apk --no-cache add libmagic && \
    pip3 install --no-cache-dir -r src/requirements.txt && \
    apk del .build-deps

COPY entrypoint.sh /
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

RUN addgroup -S opencti && adduser -S opencti -G opencti && \
    chown -R opencti:opencti /opt/opencti-connector-rst-threat-feed /entrypoint.sh

USER opencti:opencti

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD sh -c "ps | grep -q '[p]ython3'"
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
