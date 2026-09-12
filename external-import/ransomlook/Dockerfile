FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/opencti-connector-ransomlook
COPY src/requirements.txt ./requirements.txt
RUN apk --no-cache add libmagic && \
    apk --no-cache add --virtual .build-deps \
        git \
        build-base \
        libffi-dev \
        libxml2-dev \
        libxslt-dev && \
    pip3 install --no-cache-dir \
        pip==26.1.2 \
        setuptools==82.0.1 \
        wheel==0.47.0 && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps && \
    addgroup -S opencti && \
    adduser -S -D -H -G opencti opencti
COPY --chown=opencti:opencti src .
USER opencti
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD pgrep -f "^python3 main.py$" > /dev/null || exit 1
CMD ["python3", "main.py"]
