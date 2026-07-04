FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Copy the connector
COPY src /opt/opencti-connector-ioc-extractor
WORKDIR /opt/opencti-connector-ioc-extractor

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

CMD ["python3", "main.py"]
