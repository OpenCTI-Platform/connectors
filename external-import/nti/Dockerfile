FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT
ENV NTI_PACKAGE_TYPE=updated

WORKDIR /opt/opencti/NTI-connector

COPY ./src ./src

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir -r ./src/requirements.txt && \
    apk del git build-base

COPY ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]


