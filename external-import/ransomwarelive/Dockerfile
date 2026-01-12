FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
WORKDIR /opt/opencti-connector-ransomware-live

# Install Python modules
COPY requirements.txt .
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev && \
    pip3 install --upgrade pip && \
    pip3 install --upgrade pycti && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libxslt-dev libxml2-dev && \
    rm -rf /var/cache/apk/*

# Expose and entrypoint
COPY src ./src
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
ENTRYPOINT ["/bin/sh", "entrypoint.sh"]
