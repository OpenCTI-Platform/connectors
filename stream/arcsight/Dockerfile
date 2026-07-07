FROM python:3.12-alpine
ENV CONNECTOR_TYPE=STREAM

# Install needed packages
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Install needed python packages
WORKDIR /opt/opencti-connector-arcsight
COPY src/requirements.txt /opt/opencti-connector-arcsight/requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy the connector
COPY src /opt/opencti-connector-arcsight

# Expose and set the entrypoint
ENTRYPOINT ["python", "main.py"]
