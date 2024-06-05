FROM python:3.11-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install necessary packages
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector files
COPY src /opt/connector
WORKDIR /opt/connector

RUN pip3 install --no-cache-dir -r /opt/connector/requirements.txt

# Entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
