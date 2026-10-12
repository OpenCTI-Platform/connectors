FROM python:3.12-alpine

ENV CONNECTOR_TYPE=STREAM \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# connectors-sdk is installed from a git URL, so git/build tooling is needed at build time.
# libmagic is a runtime dependency of pycti (python-magic) and must remain installed.
COPY src /opt/opencti-connector-cloudflare-rules-list
WORKDIR /opt/opencti-connector-cloudflare-rules-list
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libffi-dev openssl-dev libmagic && \
    cd /opt/opencti-connector-cloudflare-rules-list && \
    pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["python3", "main.py"]
