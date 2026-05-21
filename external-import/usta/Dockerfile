FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apk add --no-cache git build-base libffi-dev openssl-dev libmagic

COPY src /opt/opencti-connector-usta

RUN cd /opt/opencti-connector-usta && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base libffi-dev openssl-dev

WORKDIR /opt/opencti-connector-usta

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
