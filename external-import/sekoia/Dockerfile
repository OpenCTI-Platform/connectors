FROM python:3.13-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /opt/opencti-connector-sekoia

COPY src/requirements.txt /opt/opencti-connector-sekoia/src/requirements.txt

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add --virtual .build-dependencies git build-base && \
    apk --no-cache add libmagic wget && \
    pip3 install --no-cache-dir -r /opt/opencti-connector-sekoia/src/requirements.txt && \
    apk del .build-dependencies && \
    rm -rf /var/cache/apk/*

# Copy the connector
COPY src /opt/opencti-connector-sekoia/src

RUN wget -O /opt/opencti-connector-sekoia/src/data/sectors.json  https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json && \
    wget -O /opt/opencti-connector-sekoia/src/data/geography.json  https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json

CMD ["python", "-m", "src"]