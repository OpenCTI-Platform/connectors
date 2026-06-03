FROM python:3.12-alpine

ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/opencti-connector-dark-web-informer

RUN apk --no-cache add git build-base libmagic libffi-dev && \
    cd /opt/opencti-connector-dark-web-informer && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
