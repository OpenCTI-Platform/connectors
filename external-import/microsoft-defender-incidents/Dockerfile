FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
WORKDIR /opt/opencti-connector-microsoft-defender-incidents
COPY src/requirements.txt .

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY src/requirements.txt .

# Expose and entrypoint
ENTRYPOINT ["python", "main.py"]