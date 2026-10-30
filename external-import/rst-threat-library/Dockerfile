FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /opt/opencti-connector-rst-threat-library

COPY src /opt/opencti-connector-rst-threat-library/src

# Install pinned deps first, then connectors-sdk with --no-deps so its pycti
RUN apk --no-cache add --virtual .build-deps git build-base && \
    apk --no-cache add libmagic && \
    grep -v '^connectors-sdk' src/requirements.txt | grep -v '^#' | grep -v '^$' > /tmp/reqs.txt && \
    pip3 install --no-cache-dir -r /tmp/reqs.txt && \
    SDK_SPEC=$(grep '^connectors-sdk' src/requirements.txt | sed 's/^connectors-sdk[[:space:]]*@[[:space:]]*//') && \
    pip3 install --no-cache-dir --no-deps "$SDK_SPEC" && \
    rm -f /tmp/reqs.txt && \
    apk del .build-deps

COPY entrypoint.sh /
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

RUN addgroup -S opencti && adduser -S opencti -G opencti && \
    chown -R opencti:opencti /opt/opencti-connector-rst-threat-library /entrypoint.sh

USER opencti:opencti

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD sh -c "ps | grep -q '[p]ython3'"
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
