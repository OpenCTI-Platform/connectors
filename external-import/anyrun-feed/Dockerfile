FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector
COPY src /opt/connector
WORKDIR /opt/connector
RUN pip3 install --no-cache-dir -r requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]