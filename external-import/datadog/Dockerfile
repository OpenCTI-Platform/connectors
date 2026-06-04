FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT \
    CONNECTOR_DIR=/opt/opencti-connector-datadog \
    PIP_BREAK_SYSTEM_PACKAGES=1

COPY src ${CONNECTOR_DIR}

WORKDIR ${CONNECTOR_DIR}

RUN apk --no-cache --virtual .build-deps add \
        git \
        build-base \
        libxslt-dev \
        libxml2-dev \
        python3-dev \
        libffi-dev \
    && apk --no-cache add libmagic \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps \
    && rm -rf /var/cache/apk/*

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
