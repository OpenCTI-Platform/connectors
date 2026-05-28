FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY requirements.txt /opt/opencti-connector-catalyst/
RUN pip3 install --no-cache-dir -r /opt/opencti-connector-catalyst/requirements.txt

COPY src /opt/opencti-connector-catalyst

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
