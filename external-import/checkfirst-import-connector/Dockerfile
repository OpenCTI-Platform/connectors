FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /opt/opencti-connector-checkfirst-import-connector

# System deps
# - ca-certificates: HTTPS/TLS trust store for OpenCTI/API calls
# - libmagic: required by python-magic (pulled by pycti on Linux)
# - libffi: common runtime dep for wheels using libffi
RUN apk add --no-cache \
    ca-certificates \
    libffi \
    libmagic

COPY src /opt/opencti-connector-checkfirst-import-connector

RUN apk add --no-cache --virtual .build-deps \
        build-base \
        git \
        libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

ENV PYTHONUNBUFFERED=1

CMD ["python3", "main.py"]
