FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Install requirements first to leverage Docker layer caching
WORKDIR /opt/opencti-connector-ctm360-threatcover
COPY src/requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy the connector
COPY src .

ENTRYPOINT ["python", "main.py"]
