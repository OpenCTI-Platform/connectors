FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY . /opt/opencti-obstracts
WORKDIR /opt/opencti-obstracts

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

RUN chmod +x entrypoint.sh

ENTRYPOINT ["/opt/opencti-obstracts/entrypoint.sh"]
