FROM python:3.12-alpine

ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

COPY src /opt/opencti-connector-polyswarm-enrichment/src
WORKDIR /opt/opencti-connector-polyswarm-enrichment/src

RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del --no-network git build-base libffi-dev libxml2-dev libxslt-dev

ENTRYPOINT ["python3", "main.py"]
