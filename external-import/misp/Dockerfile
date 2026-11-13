FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-misp
WORKDIR /opt/opencti-connector-misp

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libffi-dev && \
    cd /opt/opencti-connector-misp && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libffi-dev

CMD ["python", "main.py"]
