FROM python:3.13-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

COPY src /opt/connector-sentinelone-incidents

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/connector-sentinelone-incidents && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
