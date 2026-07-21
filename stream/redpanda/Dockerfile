FROM python:3.12-alpine
ENV CONNECTOR_TYPE=STREAM

# Copy the connector
COPY src /opt/opencti-connector-redpanda
WORKDIR /opt/opencti-connector-redpanda

# Install Python modules
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

ENTRYPOINT ["python3", "main.py"]
