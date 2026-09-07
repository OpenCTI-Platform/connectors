FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-cofense-threathq

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-cofense-threathq && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base && \
    rm -rf /var/cache/apk/*

WORKDIR /opt/opencti-connector-cofense-threathq

CMD ["python3", "main.py"]
