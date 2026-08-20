FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy requirements.txt
WORKDIR /opt/opencti-connector-flare
COPY src/requirements.txt /opt/opencti-connector-flare
RUN pip install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY src /opt/opencti-connector-flare

ENTRYPOINT ["python", "main.py"]
