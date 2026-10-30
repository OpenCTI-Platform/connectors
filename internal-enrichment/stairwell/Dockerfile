FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

WORKDIR /opt/opencti-connector-stairwell
COPY src/requirements.txt /opt/opencti-connector-stairwell
RUN pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY src /opt/opencti-connector-stairwell

ENTRYPOINT ["python", "main.py"]
