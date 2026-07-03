FROM python:3.12-alpine
ENV CONNECTOR_TYPE=STREAM

# Copy the connector
COPY src /opt/opencti-connector-vectra-ai

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-vectra-ai && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Run the connector directly so Python is PID 1 and receives container signals
WORKDIR /opt/opencti-connector-vectra-ai
ENTRYPOINT ["python3", "main.py"]
