ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-alpine AS base

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /opt/opencti-connector-rst-threat-library

# Install Python modules (SDK runtime deps included — do not use --no-deps)
# hadolint ignore=DL3003
RUN apk --no-cache upgrade \
 && apk --no-cache add --virtual .build-deps git build-base libffi-dev \
 && apk --no-cache add libmagic

COPY src /opt/opencti-connector-rst-threat-library

RUN pip3 install --no-cache-dir -r requirements.txt \
 && apk del .build-deps

COPY entrypoint.sh /
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

RUN addgroup -S opencti && adduser -S opencti -G opencti \
 && chown -R opencti:opencti /opt/opencti-connector-rst-threat-library /entrypoint.sh

USER opencti:opencti

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD sh -c "ps | grep -q '[p]ython3'"
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
