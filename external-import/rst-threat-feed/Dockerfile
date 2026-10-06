FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-threatfeed

# Install dependencies
RUN apk --no-cache add git build-base libmagic && \
    cd /opt/opencti-connector-threatfeed && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

WORKDIR /opt/opencti-connector-threatfeed
CMD ["python3", "main.py"]