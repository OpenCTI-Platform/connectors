FROM python:3.12-alpine
ENV CONNECTOR_TYPE=STREAM

# Copy the connector
COPY src /opt/opencti-connector-sumologic-intel
WORKDIR /opt/opencti-connector-sumologic-intel

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

CMD ["python3", "main.py"]
