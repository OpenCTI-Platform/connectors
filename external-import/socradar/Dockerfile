FROM python:3.12-alpine

# Copy the connector
COPY src /opt/opencti-connector-socradar

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

COPY requirements.txt .

RUN pip install -r requirements.txt --no-cache-dir --upgrade pip && \
    rm requirements.txt && \
    apk del git build-base

# Expose entrypoint.sh
COPY entrypoint.sh .

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
