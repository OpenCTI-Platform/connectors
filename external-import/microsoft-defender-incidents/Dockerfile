FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector requirements and install them
WORKDIR /opt/opencti-connector-microsoft-defender-incidents
COPY src/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy the connector source code
COPY src .

# Expose and entrypoint
ENTRYPOINT ["python", "main.py"]