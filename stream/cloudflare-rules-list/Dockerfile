FROM python:3.12-alpine

ENV CONNECTOR_TYPE=STREAM \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# connectors-sdk is installed from a git URL, so git/build tooling is needed at build time.
# libmagic is a runtime dependency of pycti (python-magic) and must remain installed.
COPY src /opt/opencti-connector-cloudflare-rules-list
RUN apk --no-cache add git build-base libffi-dev openssl-dev libmagic && \
    cd /opt/opencti-connector-cloudflare-rules-list && \
    pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
