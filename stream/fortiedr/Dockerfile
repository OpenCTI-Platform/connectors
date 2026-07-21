FROM python:3.12-alpine
ENV CONNECTOR_TYPE=STREAM

# Copy the connector
COPY src /opt/opencti-connector-fortiedr

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-fortiedr && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

WORKDIR /opt/opencti-connector-fortiedr
ENTRYPOINT ["python3", "main.py"]
