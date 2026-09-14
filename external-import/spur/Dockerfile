FROM python:3.14-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-spur

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-spur && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

RUN addgroup -S connector && adduser -S -G connector connector
USER connector
WORKDIR /opt/opencti-connector-spur

CMD ["python3", "main.py"]
