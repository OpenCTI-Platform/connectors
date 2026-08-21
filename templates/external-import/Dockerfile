FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-template

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN pip3 install --no-cache-dir -r /opt/opencti-connector-template/requirements.txt && \
    apk del git build-base

WORKDIR /opt/opencti-connector-template
CMD ["python3", "main.py"]
